use image::imageops::FilterType;
use image::io::Reader as ImageReader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
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
    RequestImageAccess {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
        prop_views: u64,
    },
    ViewPendingRequests {
        request_id: u64,
        username: String,
    },
    ApproveOrRejectAccess {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
        accep_views: i64,
    },
    GetAcceptedViews {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
    },
    ModifyViews {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
        change_views: i64,
    },
    AddViews {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
        additional_views: u64,
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

#[derive(Clone, Debug, Serialize, Deserialize)] // ✅ Added Serialize, Deserialize
pub struct PendingRequest {
    pub viewer: String,
    pub image_name: String,
    pub prop_views: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub owner: String,
    pub image_name: String,
    pub accepted_views: u64,
    pub views_count: u64,
}

pub struct Client {
    pub metadata: ClientMetadata,
    pub middleware_addr: String,
    pub tracker: RequestTracker,
    pub pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
}

impl Client {
    pub fn get_accepted_views(&self, owner: &str, image_name: &str) -> Result<u64, Box<dyn Error>> {
        let request_id = self.tracker.create_request();
        let request = ClientRequest::GetAcceptedViews {
            request_id,
            owner: owner.to_string(),
            viewer: self.metadata.username.clone(),
            image_name: image_name.to_string(),
        };

        let id = self.send_request_async(request);
        println!(
            "[Client] Queued get accepted views request #{} for {}'s '{}'",
            id, owner, image_name
        );
        Ok(id)
    }

    pub fn add_views(
        &self,
        owner: &str,
        image_name: &str,
        additional_views: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let request_id = self.tracker.create_request();
        let request = ClientRequest::AddViews {
            request_id,
            owner: owner.to_string(),
            viewer: self.metadata.username.clone(),
            image_name: image_name.to_string(),
            additional_views,
        };

        let id = self.send_request_async(request);
        println!(
            "[Client] Queued add views request #{} for +{} views of {}'s '{}'",
            id, additional_views, owner, image_name
        );
        Ok(id)
    }

    pub fn modify_views(
        &self,
        viewer: &str,
        image_name: &str,
        change_views: i64,
    ) -> Result<u64, Box<dyn Error>> {
        let request_id = self.tracker.create_request();
        let request = ClientRequest::ModifyViews {
            request_id,
            owner: self.metadata.username.clone(),
            viewer: viewer.to_string(),
            image_name: image_name.to_string(),
            change_views,
        };

        let id = self.send_request_async(request);
        let action = if change_views >= 0 {
            "increase"
        } else {
            "decrease"
        };
        println!(
            "[Client] Queued modify views request #{} to {} views for {}'s '{}' by {:+}",
            id, action, viewer, image_name, change_views
        );
        Ok(id)
    }

    pub fn view_image(&self, owner: &str, image_name: &str) -> Result<(), Box<dyn Error>> {
        let storage_dir = "shared_images";
        let image_path = format!("{}/{}", storage_dir, image_name);

        // Check if image exists
        if !Path::new(&image_path).exists() {
            return Err(format!("Image '{}' not found in shared_images", image_name).into());
        }

        println!("[Client] Viewing image: {}'s '{}'", owner, image_name);

        // Step 1: Read metadata file
        let metadata_filename = format!(
            "{}_metadata.json",
            std::path::Path::new(image_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("image")
        );
        let metadata_path = format!("{}/{}", storage_dir, metadata_filename);

        let mut metadata: ImageMetadata = if Path::new(&metadata_path).exists() {
            let metadata_json = fs::read_to_string(&metadata_path)?;
            serde_json::from_str(&metadata_json)?
        } else {
            return Err(format!("Metadata file not found: {}", metadata_path).into());
        };

        println!(
            "[Client] Current metadata - Accepted: {}, Used: {}",
            metadata.accepted_views, metadata.views_count
        );

        // Step 2: Try to contact server to get database views
        println!("[Client] Attempting to sync with server...");
        match self.get_accepted_views(owner, image_name) {
            Ok(request_id) => {
                // Wait a bit for the response
                println!(
                    "[Client] Waiting for server response (request #{})...",
                    request_id
                );
                std::thread::sleep(Duration::from_secs(2));

                // Check if we got a completed response
                if let Some(RequestStatus::Completed(response)) =
                    self.tracker.get_status(request_id)
                {
                    if response.status == "OK" {
                        // Step 3: Parse accepted views from server response
                        if let Some(message) = &response.message {
                            // Extract views from message like "Approved: 10 views remaining"
                            if let Some(views_str) = message
                                .split_whitespace()
                                .find(|s| s.parse::<u64>().is_ok())
                            {
                                if let Ok(server_views) = views_str.parse::<u64>() {
                                    println!(
                                        "[Client] ✓ Server sync successful - updating accepted views: {} -> {}",
                                        metadata.accepted_views, server_views
                                    );
                                    metadata.accepted_views = server_views;

                                    // Write updated metadata back to file
                                    let updated_json = serde_json::to_string_pretty(&metadata)?;
                                    fs::write(&metadata_path, updated_json)?;
                                    println!("[Client] ✓ Metadata updated with server views");
                                }
                            }
                        }
                    } else {
                        println!("[Client] ⚠ Server returned error, using local metadata");
                    }
                } else {
                    println!("[Client] ⚠ Server did not respond in time, using local metadata");
                }
            }
            Err(e) => {
                println!(
                    "[Client] ⚠ Could not contact server: {}, using local metadata",
                    e
                );
            }
        }

        // Step 4: Check if we have remaining views
        let remaining_views = metadata.accepted_views.saturating_sub(metadata.views_count);
        println!(
            "[Client] Remaining views: {} (accepted: {}, used: {})",
            remaining_views, metadata.accepted_views, metadata.views_count
        );

        let should_decrypt = remaining_views > 0;
        let image_to_display: String;

        if should_decrypt {
            println!(
                "[Client] ✓ You have {} views remaining - decrypting image...",
                remaining_views
            );

            // Increment view count
            metadata.views_count += 1;

            // Save updated metadata
            let updated_json = serde_json::to_string_pretty(&metadata)?;
            fs::write(&metadata_path, updated_json)?;
            println!(
                "[Client] ✓ View count incremented: {} -> {}",
                metadata.views_count - 1,
                metadata.views_count
            );

            // Decrypt the image
            match self.request_decryption(&image_path) {
                Ok(request_id) => {
                    println!(
                        "[Client] Decryption request #{} queued, waiting...",
                        request_id
                    );

                    // Wait for decryption to complete (with timeout)
                    let mut wait_time = 0;
                    let max_wait = 30; // 30 seconds timeout

                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        wait_time += 1;

                        match self.tracker.get_status(request_id) {
                            Some(RequestStatus::Completed(response)) => {
                                if let Some(output_path) = response.output_path {
                                    println!("[Client] ✓ Decryption complete: {}", output_path);
                                    image_to_display = output_path;
                                    break;
                                } else {
                                    return Err("Decryption completed but no output path".into());
                                }
                            }
                            Some(RequestStatus::Failed(err)) => {
                                return Err(format!("Decryption failed: {}", err).into());
                            }
                            _ => {
                                if wait_time >= max_wait {
                                    return Err("Decryption timed out".into());
                                }
                                // Still waiting...
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to queue decryption: {}", e).into());
                }
            }
        } else {
            println!("[Client] ⚠ No views remaining - displaying encrypted image");
            image_to_display = image_path.clone();
        }

        // Step 5: Display the image in a popup window
        println!("[Client] Opening image viewer for: {}", image_to_display);

        #[cfg(target_os = "linux")]
        {
            match Command::new("xdg-open").arg(&image_to_display).spawn() {
                Ok(_) => println!("[Client] ✓ Image opened with default viewer"),
                Err(e) => {
                    eprintln!("[Client] ✗ Could not open image viewer: {}", e);
                    eprintln!("[Client] Image saved at: {}", image_to_display);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            match Command::new("open").arg(&image_to_display).spawn() {
                Ok(_) => println!("[Client] ✓ Image opened"),
                Err(e) => eprintln!("[Client] ✗ Could not open image: {}", e),
            }
        }

        #[cfg(target_os = "windows")]
        {
            match Command::new("cmd")
                .args(&["/C", "start", "", &image_to_display])
                .spawn()
            {
                Ok(_) => println!("[Client] ✓ Image opened"),
                Err(e) => eprintln!("[Client] ✗ Could not open image: {}", e),
            }
        }

        println!("\n========================================");
        println!("Image Viewing Summary");
        println!("========================================");
        println!("Owner: {}", owner);
        println!("Image: {}", image_name);
        println!("Accepted Views: {}", metadata.accepted_views);
        println!("Views Used: {}", metadata.views_count);
        println!(
            "Remaining Views: {}",
            metadata.accepted_views.saturating_sub(metadata.views_count)
        );
        println!("Decrypted: {}", if should_decrypt { "Yes" } else { "No" });
        println!("========================================\n");

        Ok(())
    }
    pub fn view_pending_requests(&self) -> Result<u64, Box<dyn Error>> {
        let request_id = self.tracker.create_request();
        let request = ClientRequest::ViewPendingRequests {
            request_id,
            username: self.metadata.username.clone(),
        };

        // ✅ Clone for background thread
        let tracker = self.tracker.requests.clone();
        let pending_requests = self.pending_requests.clone();
        let middleware_addr = self.middleware_addr.clone();

        self.tracker
            .update_status(request_id, RequestStatus::InProgress);

        // ✅ Custom thread that stores the data
        thread::spawn(move || {
            println!(
                "[Client] [Req #{}] Sending view pending requests in background...",
                request_id
            );

            match Client::send_request_sync(&middleware_addr, &request) {
                Ok(response) => {
                    println!("[Client] [Req #{}] ✓ Completed", request_id);

                    // ✅ Parse and store the pending requests
                    if let Some(output_path) = &response.output_path {
                        if let Ok(requests) =
                            serde_json::from_str::<Vec<PendingRequest>>(output_path)
                        {
                            let mut pending = pending_requests.lock().unwrap();
                            *pending = requests.clone();
                            println!(
                                "[Client] [Req #{}] ✓ Stored {} pending requests locally",
                                request_id,
                                requests.len()
                            );
                        }
                    }

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

        println!(
            "[Client] Queued view pending requests #{} for '{}'",
            request_id, self.metadata.username
        );
        Ok(request_id)
    }

    pub fn approve_or_reject_access(
        &self,
        request_number: usize,
        accep_views: i64,
    ) -> Result<u64, Box<dyn Error>> {
        let pending = self.pending_requests.lock().unwrap();

        if request_number == 0 || request_number > pending.len() {
            return Err(
                format!("Invalid request number. Please choose 1-{}", pending.len()).into(),
            );
        }

        let req = &pending[request_number - 1];

        let request_id = self.tracker.create_request();
        let request = ClientRequest::ApproveOrRejectAccess {
            request_id,
            owner: self.metadata.username.clone(),
            viewer: req.viewer.clone(),
            image_name: req.image_name.clone(),
            accep_views,
        };

        let id = self.send_request_async(request);

        let action = if accep_views == -1 {
            "rejection"
        } else {
            "approval"
        };
        println!(
            "[Client] Queued access {} #{} for {}'s request",
            action, id, req.viewer
        );
        Ok(id)
    }

    pub fn request_image_access(
        &self,
        owner: &str,
        image_name: &str,
        prop_views: u64,
    ) -> Result<u64, Box<dyn Error>> {
        let request_id = self.tracker.create_request();
        let request = ClientRequest::RequestImageAccess {
            request_id,
            owner: owner.to_string(),
            viewer: self.metadata.username.clone(),
            image_name: image_name.to_string(),
            prop_views,
        };

        let id = self.send_request_async(request);
        println!(
            "[Client] Queued access request #{} for {}'s '{}' ({} views)",
            id, owner, image_name, prop_views
        );
        Ok(id)
    }

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
            pending_requests: Arc::new(Mutex::new(Vec::new())),
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
            ClientRequest::RequestImageAccess { request_id, .. } => *request_id,
            ClientRequest::ViewPendingRequests { request_id, .. } => *request_id,
            ClientRequest::ApproveOrRejectAccess { request_id, .. } => *request_id,
            ClientRequest::GetAcceptedViews { request_id, .. } => *request_id,
            ClientRequest::ModifyViews { request_id, .. } => *request_id,
            ClientRequest::AddViews { request_id, .. } => *request_id,
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
        println!("  request_access <owner> <image_name> <views>  - Request access to an image");
        println!("  view_pending_requests            - View access requests for your images");
        println!(
            "  approve_access_request <number> <views>  - Approve (views>0) or reject (views=-1) a request"
        );
        println!("  get_views <owner> <image_name>  - Get accepted views for an image");
        println!("  view_image <owner> <image_name>  - View a shared image from shared_images");
        println!(
            "  modify_views <viewer> <image_name> <change>  - Modify accepted views (+/- number)"
        );
        println!(
            "  add_views <owner> <image_name> <views>  - Request additional views for an approved image"
        );
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
                "request_access" if tokens.len() == 4 => {
                    let owner = tokens[1];
                    let image_name = tokens[2];
                    match tokens[3].parse::<u64>() {
                        Ok(prop_views) => {
                            match self.request_image_access(owner, image_name, prop_views) {
                                Ok(id) => println!("Request #{id} queued (requesting access)"),
                                Err(e) => eprintln!("Error: {e}"),
                            }
                        }
                        Err(_) => eprintln!("Error: prop_views must be a valid number"),
                    }
                }
                "view_pending_requests" => match self.view_pending_requests() {
                    Ok(id) => println!("Request #{id} queued (fetching pending requests)"),
                    Err(e) => eprintln!("Error: {e}"),
                },
                "approve_access_request" if tokens.len() == 3 => {
                    let request_number = match tokens[1].parse::<usize>() {
                        Ok(n) => n,
                        Err(_) => {
                            eprintln!("Error: request number must be a valid integer");
                            continue;
                        }
                    };

                    let accep_views = match tokens[2].parse::<i64>() {
                        Ok(v) => v,
                        Err(_) => {
                            eprintln!("Error: views must be a valid integer (use -1 to reject)");
                            continue;
                        }
                    };

                    if accep_views != -1 && accep_views <= 0 {
                        eprintln!("Error: views must be greater than 0 or -1 to reject");
                        continue;
                    }

                    match self.approve_or_reject_access(request_number, accep_views) {
                        Ok(id) => {
                            let action = if accep_views == -1 {
                                "rejection"
                            } else {
                                "approval"
                            };
                            println!("Request #{id} queued (access {})", action);
                        }
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "check_stored" => {
                    let pending = self.pending_requests.lock().unwrap();
                    println!("Stored requests: {}", pending.len());
                    for (i, req) in pending.iter().enumerate() {
                        println!(
                            "  [{}] {} - {} - {}",
                            i + 1,
                            req.viewer,
                            req.image_name,
                            req.prop_views
                        );
                    }
                }
                "get_views" if tokens.len() == 3 => {
                    let owner = tokens[1];
                    let image_name = tokens[2];

                    match self.get_accepted_views(owner, image_name) {
                        Ok(id) => println!("Request #{id} queued (getting accepted views)"),
                        Err(e) => eprintln!("Error: {e}"),
                    }
                }
                "view_image" if tokens.len() == 3 => {
                    let owner = tokens[1];
                    let image_name = tokens[2];

                    match self.view_image(owner, image_name) {
                        Ok(_) => println!("Image viewing complete"),
                        Err(e) => eprintln!("Error viewing image: {}", e),
                    }
                }
                "modify_views" if tokens.len() == 4 => {
                    let viewer = tokens[1];
                    let image_name = tokens[2];
                    match tokens[3].parse::<i64>() {
                        Ok(change_views) => {
                            match self.modify_views(viewer, image_name, change_views) {
                                Ok(id) => println!("Request #{id} queued (modifying views)"),
                                Err(e) => eprintln!("Error: {e}"),
                            }
                        }
                        Err(_) => eprintln!("Error: change_views must be a valid integer"),
                    }
                }
                "add_views" if tokens.len() == 4 => {
                    let owner = tokens[1];
                    let image_name = tokens[2];
                    match tokens[3].parse::<u64>() {
                        Ok(additional_views) => {
                            match self.add_views(owner, image_name, additional_views) {
                                Ok(id) => {
                                    println!("Request #{id} queued (requesting additional views)")
                                }
                                Err(e) => eprintln!("Error: {e}"),
                            }
                        }
                        Err(_) => {
                            eprintln!("Error: additional views must be a valid positive number")
                        }
                    }
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
