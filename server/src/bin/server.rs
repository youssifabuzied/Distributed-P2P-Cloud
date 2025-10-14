// =======================================
// server.rs
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Responsibilities:
// - Receive encryption requests from server middleware via TCP
// - Process requests asynchronously
// - Return encrypted (gibberish) data back to middleware
//
use std::net::{TcpListener, TcpStream};
use std::io::{BufRead, BufReader, Write};
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::thread;
use rand::Rng;
use std::fs;
use image::io::Reader as ImageReader;
use image::{DynamicImage, ImageFormat,GenericImageView};
use hex;
use std::fs::File;
use aes_gcm::{Aes256Gcm, Key};
use image::imageops::FilterType
use bincode;
use std::io::Cursor;
use stegano_core::api::hide::prepare as hide_prepare;
use stegano_core::api::unveil::prepare as extract_prepare;
use std::path::PathBuf;
use tempfile::Builder;

// =======================================
// Data Structures
// =======================================

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionRequest {
    pub request_id: u64,
    pub filename: String,
    pub file_data: Vec<u8>,  // Raw image bytes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionResponse {
    pub request_id: u64,
    pub status: String,
    pub message: String,
    pub encrypted_data: Option<Vec<u8>>,
    pub original_size: usize,
    pub encrypted_size: usize,
}
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    message: String,
    views: i32,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    extra: Option<String>,
}

impl EncryptionResponse {
    pub fn success(
        request_id: u64,
        encrypted_data: Vec<u8>,
        original_size: usize,
    ) -> Self {
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

pub struct Server {
    pub ip: String,
    pub port: u16,
}

impl Server {
    pub fn new(ip: &str, port: u16) -> Self {
        Server {
            ip: ip.to_string(),
            port,
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;
        
        println!("========================================");
        println!("Cloud P2P Server");
        println!("========================================");
        println!("[Server] Listening on {}", addr);
        println!("[Server] Ready to process encryption requests...\n");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr()
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
                println!("[Server] [Req #{}] Processing encryption for: {} ({} bytes)", 
                         request.request_id, request.filename, request.file_data.len());
                
                // Process encryption asynchronously (in this thread)
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

        println!("[Server] [Req #{}] Sent response ({} bytes encrypted)\n", 
                 response.request_id, response.encrypted_size);
        
        Ok(())
    }

    fn encrypt_data(request: EncryptionRequest) -> EncryptionResponse {

        println!("[Server] [Req #{}] Starting encryption...", request.request_id);
        let tmp_dir = PathBuf::from("/tmp/");
        if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        return EncryptionResponse {
            request_id: request.request_id,
            status: "error".into(),
            message: format!("Failed to create tmp dir: {}", e),
            encrypted_data: None,
            original_size: request.file_data.len(),
            encrypted_size: 0,
        };
        }

        let payload = HiddenPayload {
        message: format!("Hidden from file: {}", request.filename),
        views: 42,
        image_bytes: request.file_data.clone(),
        extra: Some("Metadata info".to_string()),
        };

        let serialized = match bincode::serialize(&payload) {
        Ok(s) => s,
        Err(e) => {
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

        let cover_image_path = PathBuf::from("../../resources/default_image.png");
        //let output_path = PathBuf::from("../../resources/output_stego.png");

        let mut tmp_payload = match tempfile::NamedTempFile::new_in(&tmp_dir) {
        Ok(f) => f,
        Err(e) => {
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
        if let Err(e) = tmp_payload.write_all(&serialized).and_then(|_| tmp_payload.flush()) {
        return EncryptionResponse {
            request_id: request.request_id,
            status: "error".into(),
            message: format!("Failed to write tmp payload: {}", e),
            encrypted_data: None,
            original_size: request.file_data.len(),
            encrypted_size: 0,
        };
        }
        let cover = match ImageReader::open(&cover_image_path) {
            Ok(reader) => match reader.decode() {
                Ok(img) => img,
                Err(e) => {
                    return EncryptionResponse {
                        request_id: request.request_id,
                        status: "error".into(),
                        message: format!("Failed to decode image {}: {}", cover_image_path.display(), e),
                        encrypted_data: None,
                        original_size: request.file_data.len(),
                        encrypted_size: 0,
                    };
                }
            },
            Err(e) => {
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
        let (cw, ch) = cover.dimensions();
        let payload_size = serialized.len();
        // your cover capacity heuristic from main()
        let cover_capacity = (cw as f32 * ch as f32) * 0.375f32;

        let cover_final: DynamicImage = if (payload_size as f32) > cover_capacity {
            let scale_factor = ((payload_size as f32 / cover_capacity).sqrt()).ceil();
            let new_w = (cw as f32 * scale_factor) as u32;
            let new_h = (ch as f32 * scale_factor) as u32;
            cover.resize(new_w, new_h, FilterType::Lanczos3)
        } else {
            cover
        };
        let mut cover_buf = Vec::new();
        if let Err(e) = cover_final.write_to(&mut Cursor::new(&mut cover_buf), ImageFormat::Png) {
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
        if let Err(e) = tmp_cover.write_all(&cover_buf).and_then(|_| tmp_cover.flush()) {
        return EncryptionResponse {
            request_id: request.request_id,
            status: "error".into(),
            message: format!("Failed to write tmp cover file: {}", e),
            encrypted_data: None,
            original_size: request.file_data.len(),
            encrypted_size: 0,
        };
        }
        let original_size = request.file_data.len();
        let secret_key = b"supersecretkey_supersecretkey_32";
        let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(key);
        
        let mut tmp_output = match Builder::new().suffix(".png").tempfile_in(&tmp_dir) {
        Ok(f) => f,
        Err(e) => {
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
        if let Err(e) = hide_prepare()
        .with_file(tmp_payload.path())
        .with_image(tmp_cover.path())
        .with_output(tmp_output.path())
        .using_password(password_hex.as_str())
        .execute()
        {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Steganography failed: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }
        let stego_bytes = match fs::read(tmp_output.path()) {
        Ok(bytes) => bytes,
        Err(e) => {
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
        "[Server] [Req #{}] Stego encryption complete: {} bytes → {} bytes",
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
// Entry Point
// =======================================

fn main() -> Result<(), Box<dyn Error>> {
    let server = Server::new("127.0.0.1", 7000);
    server.start()?;
    Ok(())
}