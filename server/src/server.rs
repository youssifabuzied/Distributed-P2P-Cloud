// =======================================
// server.rs - Fixed Version
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Responsibilities:
// - Receive encryption requests from server middleware via TCP
// - Process requests asynchronously
// - Return encrypted data back to middleware
//
use aes_gcm::{Aes256Gcm, Key};
use bincode;
use hex;
use image::imageops::FilterType;
use image::io::Reader as ImageReader;
use image::{DynamicImage, GenericImageView, ImageFormat};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::Cursor;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use stegano_core::api::hide::prepare as hide_prepare;
use tempfile::Builder;

// Import middleware module and its config types
mod middleware;
use middleware::{PeerInfo, ServerConfig, ServerMiddleware};

// =======================================
// Data Structures
// =======================================

/// Request structure for encryption operations
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionRequest {
    pub request_id: u64,
    pub filename: String,
    pub file_data: Vec<u8>, // Raw image bytes
}

/// Response structure for encryption operations
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionResponse {
    pub request_id: u64,
    pub status: String,
    pub message: String,
    pub encrypted_data: Option<Vec<u8>>,
    pub original_size: usize,
    pub encrypted_size: usize,
}

/// Hidden payload structure for steganography
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    message: String,
    views: i32,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    extra: Option<String>,
}

impl EncryptionResponse {
    /// Create a successful response
    pub fn success(request_id: u64, encrypted_data: Vec<u8>, original_size: usize) -> Self {
        let encrypted_size = encrypted_data.len();
        EncryptionResponse {
            request_id,
            status: "OK".to_string(),
            message: "Encryption completed successfully".to_string(),
            encrypted_data: Some(encrypted_data),
            original_size,
            encrypted_size,
        }
    }

    /// Create an error response
    pub fn error(request_id: u64, message: &str) -> Self {
        EncryptionResponse {
            request_id,
            status: "ERROR".to_string(),
            message: message.to_string(),
            encrypted_data: None,
            original_size: 0,
            encrypted_size: 0,
        }
    }
}

// =======================================
// Server
// =======================================

/// TCP server for processing encryption requests
pub struct Server {
    pub ip: String,
    pub port: u16,
}

impl Server {
    /// Create a new server instance
    pub fn new(ip: &str, port: u16) -> Self {
        Server {
            ip: ip.to_string(),
            port,
        }
    }

    /// Start the TCP server and listen for connections
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;

        println!("========================================");
        println!("Cloud P2P Server (Internal Encryption)");
        println!("========================================");
        println!("[Server] Listening on {}", addr);
        println!("[Server] Ready to process encryption requests...\n");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    println!("[Server] New connection from: {}", peer_addr);

                    // Spawn new thread for async processing
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_request(stream) {
                            eprintln!("[Server] Error handling request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[Server] Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle an incoming TCP connection and process the encryption request
    fn handle_request(stream: TcpStream) -> Result<(), Box<dyn Error>> {
        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone()?;

        // Read request line (JSON)
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        if request_line.trim().is_empty() {
            return Ok(());
        }

        println!("[Server] Received request: {} bytes", request_line.len());

        // Parse request
        let response = match serde_json::from_str::<EncryptionRequest>(request_line.trim()) {
            Ok(request) => {
                println!(
                    "[Server] [Req #{}] Processing encryption for: {} ({} bytes)",
                    request.request_id,
                    request.filename,
                    request.file_data.len()
                );

                // Process encryption
                Self::encrypt_data(request)
            }
            Err(e) => {
                eprintln!("[Server] Invalid request format: {}", e);
                EncryptionResponse::error(0, "Invalid request format")
            }
        };

        // Send response back
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        println!(
            "[Server] [Req #{}] Sent response ({} bytes encrypted)\n",
            response.request_id, response.encrypted_size
        );

        Ok(())
    }

    /// Perform steganographic encryption on the provided image data
    fn encrypt_data(request: EncryptionRequest) -> EncryptionResponse {
        println!(
            "[Server] [Req #{}] Starting encryption: {} ({} bytes)",
            request.request_id,
            request.filename,
            request.file_data.len()
        );

        // Create temp directory
        let tmp_dir = PathBuf::from("/tmp/");
        if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
            eprintln!("[Server] Failed to create tmp dir: {}", e);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to create tmp dir: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }

        // Create payload with metadata
        let payload = HiddenPayload {
            message: format!("Hidden from file: {}", request.filename),
            views: 42,
            image_bytes: request.file_data.clone(),
            extra: Some("Metadata info".to_string()),
        };

        // Serialize payload
        let serialized = match bincode::serialize(&payload) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[Server] Serialization failed: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to serialize payload: {}", e),
                    encrypted_data: None,
                    original_size: request.file_data.len(),
                    encrypted_size: 0,
                };
            }
        };

        println!(
            "[Server] [Req #{}] Serialized payload: {} bytes",
            request.request_id,
            serialized.len()
        );

        // Load cover image
        let cover_image_path = PathBuf::from("resources/default_image.png");
        let cover = match ImageReader::open(&cover_image_path) {
            Ok(reader) => match reader.decode() {
                Ok(img) => img,
                Err(e) => {
                    eprintln!("[Server] Failed to decode image: {}", e);
                    return EncryptionResponse {
                        request_id: request.request_id,
                        status: "error".into(),
                        message: format!(
                            "Failed to decode image {}: {}",
                            cover_image_path.display(),
                            e
                        ),
                        encrypted_data: None,
                        original_size: request.file_data.len(),
                        encrypted_size: 0,
                    };
                }
            },
            Err(e) => {
                eprintln!("[Server] Failed to open image: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to open image {}: {}", cover_image_path.display(), e),
                    encrypted_data: None,
                    original_size: request.file_data.len(),
                    encrypted_size: 0,
                };
            }
        };

        // Check if cover image is large enough, resize if needed
        let (cw, ch) = cover.dimensions();
        let payload_size = serialized.len();
        let cover_capacity = (cw as f32 * ch as f32) * 0.375f32;

        let cover_final: DynamicImage = if (payload_size as f32) > cover_capacity {
            let scale_factor = ((payload_size as f32 / cover_capacity).sqrt()).ceil();
            let new_w = (cw as f32 * scale_factor) as u32;
            let new_h = (ch as f32 * scale_factor) as u32;
            println!(
                "[Server] [Req #{}] Resizing cover image: {}x{} -> {}x{}",
                request.request_id, cw, ch, new_w, new_h
            );
            cover.resize(new_w, new_h, FilterType::Lanczos3)
        } else {
            cover
        };

        // Write payload to temp file
        let mut tmp_payload = match tempfile::NamedTempFile::new_in(&tmp_dir) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[Server] Failed to create temp payload file: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to create tmp payload file: {}", e),
                    encrypted_data: None,
                    original_size: request.file_data.len(),
                    encrypted_size: 0,
                };
            }
        };

        if let Err(e) = tmp_payload
            .write_all(&serialized)
            .and_then(|_| tmp_payload.flush())
        {
            eprintln!("[Server] Failed to write temp payload: {}", e);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to write tmp payload: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }

        // Write cover image to temp file
        let mut cover_buf = Vec::new();
        if let Err(e) = cover_final.write_to(&mut Cursor::new(&mut cover_buf), ImageFormat::Png) {
            eprintln!("[Server] Failed to encode resized cover: {}", e);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to encode resized cover image: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }

        let mut tmp_cover = match Builder::new().suffix(".png").tempfile_in(&tmp_dir) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[Server] Failed to create temp cover file: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to create tmp cover file: {}", e),
                    encrypted_data: None,
                    original_size: request.file_data.len(),
                    encrypted_size: 0,
                };
            }
        };

        if let Err(e) = tmp_cover
            .write_all(&cover_buf)
            .and_then(|_| tmp_cover.flush())
        {
            eprintln!("[Server] Failed to write temp cover: {}", e);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to write tmp cover file: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }

        // Prepare steganography
        let original_size = request.file_data.len();
        let secret_key = b"supersecretkey_supersecretkey_32";
        let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(key);

        let tmp_output = match Builder::new().suffix(".png").tempfile_in(&tmp_dir) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[Server] Failed to create temp output file: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to create temp output file: {}", e),
                    encrypted_data: None,
                    original_size,
                    encrypted_size: 0,
                };
            }
        };

        // Execute steganography
        println!(
            "[Server] [Req #{}] Executing steganography...",
            request.request_id
        );

        if let Err(e) = hide_prepare()
            .with_file(tmp_payload.path())
            .with_image(tmp_cover.path())
            .with_output(tmp_output.path())
            .using_password(password_hex.as_str())
            .execute()
        {
            eprintln!("[Server] Steganography execution failed: {}", e);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Steganography failed: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }

        // Read steganographic output
        let stego_bytes = match fs::read(tmp_output.path()) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[Server] Failed to read stego output: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to read stego output: {}", e),
                    encrypted_data: None,
                    original_size,
                    encrypted_size: 0,
                };
            }
        };

        println!(
            "[Server] [Req #{}] ✓ Encryption complete: {} bytes -> {} bytes",
            request.request_id,
            original_size,
            stego_bytes.len()
        );

        EncryptionResponse {
            request_id: request.request_id,
            status: "success".into(),
            message: format!(
                "Stego image successfully generated ({} bytes)",
                stego_bytes.len()
            ),
            encrypted_data: Some(stego_bytes.clone()),
            original_size,
            encrypted_size: stego_bytes.len(),
        }
    }
}

// =======================================
// Main Entry Point
// =======================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // ✨ Server configuration
    // Change these values for different server instances
    let config = ServerConfig {
        server_id: 2,               // ← Unique server ID
        priority: 20,               // ← Election priority (higher wins)
        client_port: 8000,          // ← HTTP port for client middleware
        peer_port: 8001,            // ← HTTP port for peer election
        internal_server_port: 7000, // ← TCP port for encryption server
        peers: vec![
            // Add other server instances here
            PeerInfo {
                server_id: 1,
                address: "10.40.40.202:8001".to_string(), // Server 2's peer port
            },
            // PeerInfo {
            //     server_id: 3,
            //     address: "192.168.1.10:8001".to_string(),
            // },
        ],
        election_timeout_ms: 7000, // Wait 2 seconds for election responses
    };

    println!("\n========================================");
    println!("Starting Server Instance #{}", config.server_id);
    println!("Priority: {}", config.priority);
    println!("========================================\n");

    // Start internal TCP server for encryption processing
    let internal_port = config.internal_server_port;
    let server = Server::new("127.0.0.1", internal_port);
    let server_handle = std::thread::spawn(move || {
        if let Err(e) = server.start() {
            eprintln!("[Server] TCP server error: {}", e);
        }
    });

    // Give the TCP server a moment to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Start async ServerMiddleware with election support
    let server_middleware = ServerMiddleware::new(config);
    server_middleware.start().await?;

    // Join the TCP server thread (this will block indefinitely)
    let _ = server_handle.join();

    Ok(())
}
