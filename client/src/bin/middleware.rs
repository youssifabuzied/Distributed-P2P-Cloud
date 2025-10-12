// =======================================
// middleware.rs - Updated for Async Client
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Now handles requests with request_id for tracking
//
use std::net::{TcpListener, TcpStream};
use std::io::{BufRead, BufReader, Write};
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::thread;
use std::path::Path;

// ---------------------------------------
// Shared Structures
// ---------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    EncryptImage { 
        request_id: u64,
        image_path: String 
    },
    DecryptImage { 
        request_id: u64,
        image_path: String 
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MiddlewareResponse {
    pub request_id: u64,
    pub status: String,
    pub message: Option<String>,
    pub output_path: Option<String>,
}

impl MiddlewareResponse {
    pub fn success(request_id: u64, message: &str, output_path: Option<String>) -> Self {
        MiddlewareResponse {
            request_id,
            status: "OK".to_string(),
            message: Some(message.to_string()),
            output_path,
        }
    }

    pub fn error(request_id: u64, message: &str) -> Self {
        MiddlewareResponse {
            request_id,
            status: "ERROR".to_string(),
            message: Some(message.to_string()),
            output_path: None,
        }
    }
}

// ---------------------------------------
// Client Middleware
// ---------------------------------------

pub struct ClientMiddleware {
    pub ip: String,
    pub port: u16,
}

impl ClientMiddleware {
    pub fn new(ip: &str, port: u16) -> Self {
        ClientMiddleware {
            ip: ip.to_string(),
            port,
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;
        
        println!("========================================");
        println!("Cloud P2P Client Middleware (Async)");
        println!("========================================");
        println!("[Middleware] Listening on {}", addr);
        println!("[Middleware] Ready to process async requests...\n");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    
                    println!("[Middleware] New connection from: {}", peer_addr);
                    
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client_request(stream) {
                            eprintln!("[Middleware] Error handling request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[Middleware] Connection error: {}", e);
                }
            }
        }
        
        Ok(())
    }

    fn handle_client_request(stream: TcpStream) -> Result<(), Box<dyn Error>> {
        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone()?;
        
        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        
        if request_line.trim().is_empty() {
            return Ok(());
        }

        println!("[Middleware] Received: {}", request_line.trim());

        // Parse request
        let response = match serde_json::from_str::<ClientRequest>(request_line.trim()) {
            Ok(request) => {
                let request_id = match &request {
                    ClientRequest::EncryptImage { request_id, .. } => *request_id,
                    ClientRequest::DecryptImage { request_id, .. } => *request_id,
                };
                println!("[Middleware] Processing request #{}: {:?}", request_id, request);
                Self::process_request(request)
            }
            Err(e) => {
                eprintln!("[Middleware] Invalid request format: {}", e);
                MiddlewareResponse::error(0, "Invalid request format")
            }
        };

        // Send response
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        println!("[Middleware] Sent response for request #{}\n", response.request_id);
        
        Ok(())
    }

    fn process_request(request: ClientRequest) -> MiddlewareResponse {
        match request {
            ClientRequest::EncryptImage { request_id, image_path } => {
                Self::encrypt_image(request_id, &image_path)
            }
            ClientRequest::DecryptImage { request_id, image_path } => {
                Self::decrypt_image(request_id, &image_path)
            }
        }
    }

    fn encrypt_image(request_id: u64, image_path: &str) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Image file not found");
        }

        // Simulate encryption
        println!("[Middleware] [Req #{}] Encrypting: {}", request_id, image_path);
        
        // Simulate processing time
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Generate output path
        let output_path = format!("{}.encrypted", image_path);
        
        println!("[Middleware] [Req #{}] Encryption complete: {}", request_id, output_path);
        
        MiddlewareResponse::success(
            request_id,
            "Image encrypted successfully",
            Some(output_path)
        )
    }

    fn decrypt_image(request_id: u64, image_path: &str) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Image file not found");
        }

        // Simulate decryption
        println!("[Middleware] [Req #{}] Decrypting: {}", request_id, image_path);
        
        // Simulate processing time
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        // Generate output path
        let output_path = if image_path.ends_with(".encrypted") {
            image_path.strip_suffix(".encrypted").unwrap().to_string()
        } else {
            format!("{}.decrypted", image_path)
        };
        
        println!("[Middleware] [Req #{}] Decryption complete: {}", request_id, output_path);
        
        MiddlewareResponse::success(
            request_id,
            "Image decrypted successfully",
            Some(output_path)
        )
    }
}

// ---------------------------------------
// Entry Point
// ---------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let middleware = ClientMiddleware::new("127.0.0.1", 9000);
    middleware.start()?;
    Ok(())
}