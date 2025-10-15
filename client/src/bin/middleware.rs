// =======================================
// middleware.rs - Updated to forward to Server Middleware
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Forwards encryption/decryption requests to server middleware via HTTP
//
use std::net::{TcpListener, TcpStream};
use std::io::{BufRead, BufReader, Write};
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::thread;
use std::path::Path;
use std::fs;
use base64::{Engine as _, engine::general_purpose};
use aes_gcm::{Aes256Gcm, Key};
use hex;
use bincode;
use stegano_core::api::unveil::prepare as extract_prepare;

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

#[derive(Deserialize, Debug)]
pub struct ServerResponse {
    pub request_id: u64,
    pub status: String,
    pub message: String,
    pub output_filename: Option<String>,
    pub file_data: Option<String>,  // Base64 encoded
    pub file_size: Option<usize>,
}
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    message: String,
    views: i32,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    extra: Option<String>,
}

// ---------------------------------------
// Client Middleware
// ---------------------------------------

pub struct ClientMiddleware {
    pub ip: String,
    pub port: u16,
    pub server_url: String,  // Server middleware HTTP URL
}

impl ClientMiddleware {
    pub fn new(ip: &str, port: u16, server_url: &str) -> Self {
        ClientMiddleware {
            ip: ip.to_string(),
            port,
            server_url: server_url.to_string(),
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;
        
        println!("========================================");
        println!("Cloud P2P Client Middleware");
        println!("========================================");
        println!("[ClientMiddleware] Listening on {}", addr);
        println!("[ClientMiddleware] Server URL: {}", self.server_url);
        println!("[ClientMiddleware] Ready to forward requests...\n");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    
                    println!("[ClientMiddleware] New connection from: {}", peer_addr);
                    
                    let server_url = self.server_url.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client_request(stream, &server_url) {
                            eprintln!("[ClientMiddleware] Error handling request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[ClientMiddleware] Connection error: {}", e);
                }
            }
        }
        
        Ok(())
    }

    fn handle_client_request(stream: TcpStream, server_url: &str) -> Result<(), Box<dyn Error>> {
        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone()?;
        
        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        
        if request_line.trim().is_empty() {
            return Ok(());
        }

        println!("[ClientMiddleware] Received from client: {}", request_line.trim());

        // Parse request
        let response = match serde_json::from_str::<ClientRequest>(request_line.trim()) {
            Ok(request) => {
                let request_id = match &request {
                    ClientRequest::EncryptImage { request_id, .. } => *request_id,
                    ClientRequest::DecryptImage { request_id, .. } => *request_id,
                };
                
                println!("[ClientMiddleware] [Req #{}] Forwarding to server middleware...", request_id);
                
                // Forward to server middleware (blocks until response)
                Self::forward_to_server(server_url, request)
            }
            Err(e) => {
                eprintln!("[ClientMiddleware] Invalid request format: {}", e);
                MiddlewareResponse::error(0, "Invalid request format")
            }
        };

        // Send response back to client
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        println!("[ClientMiddleware] Sent response to client for request #{}\n", response.request_id);
        
        Ok(())
    }

    fn forward_to_server(server_url: &str, request: ClientRequest) -> MiddlewareResponse {
        match request {
            ClientRequest::EncryptImage { request_id, image_path } => {
                // Forward encryption to server
                Self::send_encrypt_request(server_url, request_id, &image_path)
            }
            ClientRequest::DecryptImage { request_id, image_path } => {
                // Handle decryption locally (don't forward to server)
                Self::decrypt_image_locally(request_id, &image_path)
            }
        }
    }

    // New local decryption function (dummy implementation)
    fn decrypt_image_locally(request_id: u64, image_path: &str) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Encrypted file not found");
        }

        println!("[ClientMiddleware] [Req #{}] Decrypting locally: {}", request_id, image_path);

        let tmp_extract_dir = match tempfile::tempdir_in("/tmp") {
            Ok(dir) => dir,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to create temp folder: {}", e),
                );
            }
        };
        println!("Temporary extraction folder: {}", tmp_extract_dir.path().display());

        //println!("[ClientMiddleware] [Req #{}] Read {} bytes", request_id, file_data.len());

        let secret_key = b"supersecretkey_supersecretkey_32";
        let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(key);
        if let Err(e) = extract_prepare()
            .using_password(password_hex.as_str())
            .from_secret_file(image_path)
            .into_output_folder(tmp_extract_dir.path())
            .execute()
        {
            return MiddlewareResponse::error(
                request_id,
                &format!("Failed to extract hidden data: {}", e),
            );
        }

        println!("Extracted payload to {}", tmp_extract_dir.path().display());
        let extracted_file_path = match fs::read_dir(tmp_extract_dir.path())
            .and_then(|mut rd| rd.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No extracted file found")
            })?.map(|e| e.path()))
        {
            Ok(path) => path,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to locate extracted file: {}", e),
                );
            }
        };
        println!("Found extracted file: {}", extracted_file_path.display());
        let extracted_bytes = match fs::read(&extracted_file_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to read extracted file: {}", e),
                );
            }
        };
        println!("Extracted size: {} bytes", extracted_bytes.len());
        println!("First 32 bytes: {:?}", &extracted_bytes[..32.min(extracted_bytes.len())]);

        let recovered: HiddenPayload = match bincode::deserialize(&extracted_bytes) {
            Ok(payload) => payload,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to deserialize payload: {}", e),
                );
            }
        };
        println!("Recovered message: {}", recovered.message);
        println!("Views: {}", recovered.views);
        if let Some(extra) = &recovered.extra {
            println!("Extra: {}", extra);
        }
        let output_path = format!("{}_recovered.png", image_path);
        match fs::write(&output_path, &recovered.image_bytes) {
            Ok(_) => {
                println!(
                    "[ClientMiddleware] [Req #{}] Decryption complete → saved hidden image as: {}",
                    request_id, output_path
                );
                MiddlewareResponse::success(
                    request_id,
                    &format!("Image successfully decrypted and saved to {}", output_path),
                    Some(output_path),
                )
            }
            Err(e) => MiddlewareResponse::error(
                request_id,
                &format!("Failed to save recovered image: {}", e),
            ),
        }
    }
    fn send_encrypt_request(
        server_url: &str, 
        request_id: u64, 
        image_path: &str
    ) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Image file not found");
        }

        println!("[ClientMiddleware] [Req #{}] Reading file: {}", request_id, image_path);

        // Read file
        let file_data = match fs::read(image_path) {
            Ok(data) => data,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id, 
                    &format!("Failed to read file: {}", e)
                );
            }
        };

        let filename = Path::new(image_path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        println!("[ClientMiddleware] [Req #{}] Sending {} bytes to server", 
                 request_id, file_data.len());

        // Create multipart form using reqwest blocking client
        let client = reqwest::blocking::Client::new();
        let url = format!("{}/encrypt", server_url);
        
        let form = reqwest::blocking::multipart::Form::new()
            .text("request_id", request_id.to_string())
            .text("filename", filename.clone())
            .part("file", reqwest::blocking::multipart::Part::bytes(file_data)
                .file_name(filename));

        // Send HTTP POST request (blocks until response)
        match client.post(&url).multipart(form).send() {
            Ok(response) => {
                match response.json::<ServerResponse>() {
                    Ok(server_resp) => {
                        println!("[ClientMiddleware] [Req #{}] Received response from server: {}", 
                                 request_id, server_resp.status);

                        if server_resp.status == "OK" {
                            // Save returned file if present
                            if let (Some(file_data_b64), Some(output_filename)) = 
                                (&server_resp.file_data, &server_resp.output_filename) {
                                
                                match general_purpose::STANDARD.decode(file_data_b64) {
                                    Ok(file_data) => {
                                        let output_path = format!("./{}", output_filename);
                                        
                                        if let Err(e) = fs::write(&output_path, file_data) {
                                            eprintln!("[ClientMiddleware] Failed to save file: {}", e);
                                        } else {
                                            println!("[ClientMiddleware] [Req #{}] Saved encrypted file: {}", 
                                                     request_id, output_path);
                                        }
                                        
                                        return MiddlewareResponse::success(
                                            request_id,
                                            &server_resp.message,
                                            Some(output_path)
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("[ClientMiddleware] Base64 decode error: {}", e);
                                    }
                                }
                            }
                            
                            MiddlewareResponse::success(
                                request_id,
                                &server_resp.message,
                                server_resp.output_filename.clone()
                            )
                        } else {
                            MiddlewareResponse::error(request_id, &server_resp.message)
                        }
                    }
                    Err(e) => {
                        MiddlewareResponse::error(
                            request_id, 
                            &format!("Failed to parse server response: {}", e)
                        )
                    }
                }
            }
            Err(e) => {
                MiddlewareResponse::error(
                    request_id, 
                    &format!("Failed to send request to server: {}", e)
                )
            }
        }
    }

    fn send_decrypt_request(
        server_url: &str, 
        request_id: u64, 
        image_path: &str
    ) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Encrypted file not found");
        }

        println!("[ClientMiddleware] [Req #{}] Reading file: {}", request_id, image_path);

        // Read file
        let file_data = match fs::read(image_path) {
            Ok(data) => data,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id, 
                    &format!("Failed to read file: {}", e)
                );
            }
        };

        let filename = Path::new(image_path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        println!("[ClientMiddleware] [Req #{}] Sending {} bytes to server", 
                 request_id, file_data.len());

        // Create multipart form
        let client = reqwest::blocking::Client::new();
        let url = format!("{}/decrypt", server_url);
        
        let form = reqwest::blocking::multipart::Form::new()
            .text("request_id", request_id.to_string())
            .text("filename", filename.clone())
            .part("file", reqwest::blocking::multipart::Part::bytes(file_data)
                .file_name(filename));

        // Send HTTP POST request
        match client.post(&url).multipart(form).send() {
            Ok(response) => {
                match response.json::<ServerResponse>() {
                    Ok(server_resp) => {
                        println!("[ClientMiddleware] [Req #{}] Received response from server: {}", 
                                 request_id, server_resp.status);

                        if server_resp.status == "OK" {
                            // Save returned file if present
                            if let (Some(file_data_b64), Some(output_filename)) = 
                                (&server_resp.file_data, &server_resp.output_filename) {
                                
                                match general_purpose::STANDARD.decode(file_data_b64) {
                                    Ok(file_data) => {
                                        let output_path = format!("./{}", output_filename);
                                        
                                        if let Err(e) = fs::write(&output_path, file_data) {
                                            eprintln!("[ClientMiddleware] Failed to save file: {}", e);
                                        } else {
                                            println!("[ClientMiddleware] [Req #{}] Saved decrypted file: {}", 
                                                     request_id, output_path);
                                        }
                                        
                                        return MiddlewareResponse::success(
                                            request_id,
                                            &server_resp.message,
                                            Some(output_path)
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("[ClientMiddleware] Base64 decode error: {}", e);
                                    }
                                }
                            }
                            
                            MiddlewareResponse::success(
                                request_id,
                                &server_resp.message,
                                server_resp.output_filename.clone()
                            )
                        } else {
                            MiddlewareResponse::error(request_id, &server_resp.message)
                        }
                    }
                    Err(e) => {
                        MiddlewareResponse::error(
                            request_id, 
                            &format!("Failed to parse server response: {}", e)
                        )
                    }
                }
            }
            Err(e) => {
                MiddlewareResponse::error(
                    request_id, 
                    &format!("Failed to send request to server: {}", e)
                )
            }
        }
    }
}

// ---------------------------------------
// Entry Point
// ---------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let middleware = ClientMiddleware::new(
        "127.0.0.1", 
        9000,
        "http://127.0.0.1:8000"  // Server middleware URL
    );
    middleware.start()?;
    Ok(())
}