use image::imageops::FilterType;
use image::io::Reader as ImageReader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Data Structures

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientMetadata {
    pub username: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)] //CLIENT REQUESTS ADDED TO INCLUDE USERNAME
pub enum ClientRequest {
    EncryptImage {
        request_id: u64,
        image_path: String,
        views: HashMap<String, u64>,
    },
    DecryptImage {
        request_id: u64,
        image_path: String,
        username: String,
    },
    RegisterWithDirectory {
        request_id: u64,
        username: String,
        ip: String,
    },
    AddImage {
        request_id: u64,
        username: String,
        image_name: String,
        image_bytes: Vec<u8>,
    },
    Heartbeat {
        request_id: u64,
        username: String,
    },
    FetchActiveUsers {
        request_id: u64,
    },
    FetchUserImages {
        request_id: u64,
        target_username: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiddlewareResponse {
    pub request_id: u64,
    pub status: String,
    pub message: Option<String>,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RequestStatus {
    Pending,
    InProgress,
    Completed(MiddlewareResponse),
    Failed(String),
}

// Request Tracker

pub struct RequestTracker {
    requests: Arc<Mutex<HashMap<u64, RequestStatus>>>,
    next_id: Arc<Mutex<u64>>,
}

impl RequestTracker {
    pub fn new() -> Self {
        RequestTracker {
            requests: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    pub fn create_request(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap();
        let request_id = *id;
        *id += 1;

        self.requests
            .lock()
            .unwrap()
            .insert(request_id, RequestStatus::Pending);
        request_id
    }

    pub fn update_status(&self, id: u64, status: RequestStatus) {
        self.requests.lock().unwrap().insert(id, status);
    }

    pub fn get_status(&self, id: u64) -> Option<RequestStatus> {
        self.requests.lock().unwrap().get(&id).cloned()
    }

    pub fn list_all(&self) -> Vec<(u64, RequestStatus)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .values()
            .filter(|s| matches!(s, RequestStatus::Pending | RequestStatus::InProgress))
            .count()
    }
}

// Async Client Definition

pub struct Client {
    pub metadata: ClientMetadata,
    pub middleware_addr: String,
    pub tracker: RequestTracker,
}

impl Client {
    fn resize_image_to_100x100(image_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        // Open the image
        let img = ImageReader::open(image_path)?.decode()?;

        // Resize to 100x100 using Lanczos3 filter (high quality)
        let resized = img.resize_exact(100, 100, FilterType::Lanczos3);

        // Encode as PNG
        let mut png_bytes = Vec::new();
        resized.write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            image::ImageFormat::Png,
        )?;

        Ok(png_bytes)
    }
    /// Start sending heartbeat signals every 20 seconds
    pub fn start_heartbeat(&self) {
        let username = self.metadata.username.clone();
        let middleware_addr = self.middleware_addr.clone();
        let tracker = self.tracker.requests.clone();

        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(20));

                // Create heartbeat request
                let request_id = {
                    static HEARTBEAT_ID: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(1_000_000);
                    HEARTBEAT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                };

                let request = ClientRequest::Heartbeat {
                    request_id,
                    username: username.clone(),
                };

                // Send heartbeat (silently, no status tracking)
                let _ = Self::send_request_sync(&middleware_addr, &request);
            }
        });
    }
    pub fn new(username: &str, ip: &str, port: u16, middleware_addr: &str) -> Self {
        Client {
            metadata: ClientMetadata {
                username: username.to_string(),
                ip: ip.to_string(),
                port,
            },
            middleware_addr: middleware_addr.to_string(),
            tracker: RequestTracker::new(),
        }
    }

    /// Send request in background thread (non-blocking)
    pub fn send_request_async(&self, request: ClientRequest) -> u64 {
        let request_id = match &request {
            ClientRequest::EncryptImage { request_id, .. } => *request_id,
            ClientRequest::DecryptImage { request_id, .. } => *request_id,
            ClientRequest::RegisterWithDirectory { request_id, .. } => *request_id,
            ClientRequest::AddImage { request_id, .. } => *request_id,
            ClientRequest::Heartbeat { request_id, .. } => *request_id,
            ClientRequest::FetchActiveUsers { request_id } => *request_id,
            ClientRequest::FetchUserImages { request_id, .. } => *request_id,
        };

        let middleware_addr = self.middleware_addr.clone();
        let tracker = self.tracker.requests.clone();

        // Update status to in-progress
        self.tracker
            .update_status(request_id, RequestStatus::InProgress);

        // Spawn background thread
        thread::spawn(move || {
            println!(
                "[Client] [Req #{}] Sending request in background...",
                request_id
            );

            match Self::send_request_sync(&middleware_addr, &request) {
                Ok(response) => {
                    println!("[Client] [Req #{}] ✓ Completed", request_id);
                    tracker
                        .lock()
                        .unwrap()
                        .insert(request_id, RequestStatus::Completed(response));
                }
                Err(e) => {
                    eprintln!("[Client] [Req #{}] ✗ Failed: {}", request_id, e);
                    tracker
                        .lock()
                        .unwrap()
                        .insert(request_id, RequestStatus::Failed(e.to_string()));
                }
            }
        });

        request_id
    }

    /// Internal: Synchronous request (runs in background thread)
    fn send_request_sync(
        middleware_addr: &str,
        request: &ClientRequest,
    ) -> Result<MiddlewareResponse, Box<dyn Error>> {
        // Connect to middleware
        let stream = TcpStream::connect(middleware_addr)?;
        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone()?;

        // Serialize and send request
        let serialized = serde_json::to_string(request)?;
        writer.write_all(serialized.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        // Read response
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        // Parse response
        let response: MiddlewareResponse = serde_json::from_str(response_line.trim())?;
        Ok(response)
    }
    //Helper Function To Print User-View Pairs
    // fn format_views(views: &HashMap<String, u64>) -> String {
    // views
    //     .iter()
    //     .map(|(user, value)| format!("{}={}", user, value))
    //     .collect::<Vec<_>>()
    //     .join(", ")
    // }

    /// Request encryption (async)
    //VIEWS NEED TO CHANGE
    pub fn request_encryption(
        &self,
        image_path: &str,
        views: HashMap<String, u64>,
    ) -> Result<u64, Box<dyn Error>> {
        if !Path::new(image_path).exists() {
            return Err("Image file not found".into());
        }

        let request_id = self.tracker.create_request();
        let request = ClientRequest::EncryptImage {
            request_id,
            image_path: image_path.to_string(),
            views: views.clone(),
        };

        let id = self.send_request_async(request);
        println!(
            "[Client] Queued encryption request #{} for '{}' ({:?})",
            id, image_path, views
        );
        Ok(id)
    }

    /// Request decryption (async)
    pub fn request_decryption(&self, image_path: &str) -> Result<u64, Box<dyn Error>> {
        if !Path::new(image_path).exists() {
            return Err("Image file not found".into());
        }

        let request_id = self.tracker.create_request();
        let request = ClientRequest::DecryptImage {
            request_id,
            image_path: image_path.to_string(),
            username: self.metadata.username.clone(),
        };

        let id = self.send_request_async(request);
        println!(
            "[Client] Queued decryption request #{} for '{}'",
            id, image_path
        );
        Ok(id)
    }

    /// Check status of a specific request
    pub fn check_status(&self, request_id: u64) {
        match self.tracker.get_status(request_id) {
            Some(RequestStatus::Pending) => {
                println!("Request #{}: ⏳ Pending", request_id);
            }
            Some(RequestStatus::InProgress) => {
                println!("Request #{}: 🔄 In Progress", request_id);
            }
            Some(RequestStatus::Completed(response)) => {
                println!("Request #{}: ✓ Completed", request_id);
                println!("  Status: {}", response.status);
                if let Some(msg) = &response.message {
                    println!("  Message: {}", msg);
                }
                if let Some(path) = &response.output_path {
                    println!("  Output: {}", path);
                }
            }
            Some(RequestStatus::Failed(err)) => {
                println!("Request #{}: ✗ Failed - {}", request_id, err);
            }
            None => {
                println!("Request #{}: Not found", request_id);
            }
        }
    }

    /// List all requests
    pub fn list_requests(&self) {
        let requests = self.tracker.list_all();

        if requests.is_empty() {
            println!("No requests yet.");
            return;
        }

        println!("\n========================================");
        println!("Request History");
        println!("========================================");

        for (id, status) in requests {
            match status {
                RequestStatus::Pending => {
                    println!("#{:3} | ⏳ Pending", id);
                }
                RequestStatus::InProgress => {
                    println!("#{:3} | 🔄 In Progress", id);
                }
                RequestStatus::Completed(ref response) => {
                    println!(
                        "#{:3} | ✓ Completed - {}",
                        id,
                        response.output_path.as_ref().unwrap_or(&"N/A".to_string())
                    );
                }
                RequestStatus::Failed(ref err) => {
                    println!("#{:3} | ✗ Failed - {}", id, err);
                }
            }
        }

        let pending = self.tracker.pending_count();
        println!("========================================");
        println!("Pending/In-Progress: {}", pending);
        println!();
    }

    /// Interactive CLI
    pub fn start_ui(&self) {
        println!("========================================");
        println!("Client ");
        println!("========================================");
        println!("Welcome, {}!", self.metadata.username);
        println!("Middleware: {}", self.middleware_addr);
        println!("\nCommands:");
        println!("  register                         - Register with directory service");
        println!("  add_image <image_path>           - Add image to directory");
        // println!("  status <request_id>              - Check request status");
        println!(
            "  encrypt <image_path>, <user1>=<views1>    - Queue encryption (returns immediately)"
        );
        println!("  decrypt <image_path>     - Queue decryption (returns immediately)");
        println!("  fetch_users                      - Fetch all active users");
        println!("  fetch_images <username>          - Fetch all images of a user");

        // println!("  list                     - List all requests");
        // println!("  pending                  - Show pending count");
        println!("  exit                     - Exit the client");
        println!("========================================");

        loop {
            print!("> ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let tokens: Vec<&str> = input.trim().split_whitespace().collect();

            if tokens.is_empty() {
                continue;
            }

            match tokens[0] {
                "register" => {
                    let request_id = self.tracker.create_request();
                    let request = ClientRequest::RegisterWithDirectory {
                        request_id,
                        username: self.metadata.username.clone(),
                        ip: self.metadata.ip.clone(),
                    };

                    let id = self.send_request_async(request);
                    println!("Request #{id} queued (registering with directory service)");

                    // Start heartbeat after registration
                    self.start_heartbeat();
                    println!("Heartbeat started (every 20 seconds)");
                }
                "add_image" if tokens.len() == 2 => {
                    let image_path = tokens[1];

                    // Extract image name from path
                    let image_name = Path::new(image_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    // Read and resize image to 100x100
                    match Self::resize_image_to_100x100(image_path) {
                        Ok(resized_bytes) => {
                            let request_id = self.tracker.create_request();
                            let request = ClientRequest::AddImage {
                                request_id,
                                username: self.metadata.username.clone(),
                                image_name: image_name.to_string(),
                                image_bytes: resized_bytes,
                            };
                            let id = self.send_request_async(request);
                            println!(
                                "Request #{id} queued (adding resized 100x100 image '{}' to directory)",
                                image_name
                            );
                        }
                        Err(e) => eprintln!("Error resizing image: {e}"),
                    }
                }
                "encrypt" if tokens.len() == 3 => {
                    let image_path = tokens[1];
                    let mut user_views: HashMap<String, u64> = HashMap::new();
                    let mut invalid = false;
                    for pair in &tokens[2..] {
                        if let Some((user, value_str)) = pair.split_once('=') {
                            match value_str.parse::<u64>() {
                                Ok(value) => {
                                    user_views.insert(user.to_string(), value);
                                }
                                Err(_) => {
                                    eprintln!("Error: value for '{user}' must be a valid integer");
                                    invalid = true;
                                    break;
                                }
                            }
                        } else {
                            eprintln!("Error: invalid format '{pair}', expected username=value");
                            invalid = true;
                            break;
                        }
                    }
                    if invalid {
                        continue;
                    }
                    if user_views.is_empty() {
                        eprintln!("Error: you must provide at least one username=value pair");
                        continue;
                    }
                    match self.request_encryption(image_path, user_views) {
                        Ok(id) => println!("Request #{id} queued (background processing)"),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "decrypt" if tokens.len() == 2 => match self.request_decryption(tokens[1]) {
                    Ok(id) => {
                        println!("Request #{id} queued (background processing)");
                    }
                    Err(e) => eprintln!("Error: {e}"),
                },
                "status" if tokens.len() == 2 => {
                    if let Ok(id) = tokens[1].parse::<u64>() {
                        self.check_status(id);
                    } else {
                        println!("Invalid request ID");
                    }
                }
                "list" => {
                    self.list_requests();
                }
                "pending" => {
                    let count = self.tracker.pending_count();
                    println!("Pending/In-Progress requests: {count}");
                }
                "fetch_users" => {
                    let request_id = self.tracker.create_request();
                    let request = ClientRequest::FetchActiveUsers { request_id };
                    let id = self.send_request_async(request);
                    println!("Request #{id} queued (fetching active users)");
                }
                "fetch_images" if tokens.len() == 2 => {
                    let target_username = tokens[1];
                    let request_id = self.tracker.create_request();
                    let request = ClientRequest::FetchUserImages {
                        request_id,
                        target_username: target_username.to_string(),
                    };
                    let id = self.send_request_async(request);
                    println!(
                        "Request #{id} queued (fetching images for '{}')",
                        target_username
                    );
                }
                "exit" => {
                    let pending = self.tracker.pending_count();
                    if pending > 0 {
                        println!("Warning: {pending} request(s) still pending!");
                        print!("Exit anyway? (y/n): ");
                        io::stdout().flush().unwrap();

                        let mut confirm = String::new();
                        io::stdin().read_line(&mut confirm).unwrap();

                        if confirm.trim().to_lowercase() != "y" {
                            continue;
                        }
                    }
                    println!("Goodbye!");
                    break;
                }
                _ => println!("Invalid command. Type 'help' for available commands."),
            }
        }
    }
}
