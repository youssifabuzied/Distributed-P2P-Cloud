// =======================================
// middleware.rs - Updated to forward to Server Middleware
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Forwards encryption/decryption requests to server middleware via HTTP
//
use aes_gcm::{Aes256Gcm, Key};
use base64::{Engine as _, engine::general_purpose};
use bincode;
use hex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use stegano_core::api::unveil::prepare as extract_prepare;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};
use png::{Encoder, Decoder, TextChunk};
use std::fs::File;

// ---------------------------------------
// Shared Structures
// ---------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest { //VIEWS NEED TO CHANGE
    EncryptImage {
        request_id: u64,
        image_path: String,
        views: HashMap<String, u64>, // Map of peer ID to allowed views
    },
    DecryptImage {
        request_id: u64,
        image_path: String,
        username: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    pub file_data: Option<String>, // Base64 encoded
    pub file_size: Option<usize>,
}
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload { //VIEWS NEED TO CHANGE + VIEWS NO LONGER IN PAYLOAD!!!!
    message: String,
    // views: HashMap<String, u64>,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    // extra: Option<String>,
}

// ---------------------------------------
// Client Middleware
// ---------------------------------------

pub struct ClientMiddleware {
    pub ip: String,
    pub port: u16,
    pub server_urls: Vec<String>, // Server middleware HTTP URL
}

impl ClientMiddleware {
    pub fn new(ip: &str, port: u16, server_urls: Vec<String>) -> Self {
        ClientMiddleware {
            ip: ip.to_string(),
            port,
            server_urls,
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;

        println!("========================================");
        println!("Client Middleware ");
        println!("========================================");
        println!("[ClientMiddleware] Listening on {}]\n", addr);
        println!("[ClientMiddleware] Available servers:");
        for (i, url) in self.server_urls.iter().enumerate() {
            println!("  [{}] {}", i + 1, url);
        }

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    println!("[ClientMiddleware] New connection from: {}", peer_addr);

                    let server_urls = self.server_urls.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client_request(stream, &server_urls) {
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

    fn handle_client_request(
        stream: TcpStream,
        server_urls: &[String],
    ) -> Result<(), Box<dyn Error>> {
        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone()?;

        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        if request_line.trim().is_empty() {
            return Ok(());
        }

        println!(
            "[ClientMiddleware] Received from client: {}",
            request_line.trim()
        );

        // Parse request
        let response = match serde_json::from_str::<ClientRequest>(request_line.trim()) {
            Ok(request) => {
                let request_id = match &request {
                    ClientRequest::EncryptImage { request_id, .. } => *request_id,
                    ClientRequest::DecryptImage { request_id, .. } => *request_id,
                };

                println!(
                    "[ClientMiddleware] [Req #{}] Processing request...",
                    request_id
                );

                // Forward to appropriate handler
                Self::forward_to_servers(server_urls, request)
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

        println!(
            "[ClientMiddleware] Sent response to client for request #{}\n",
            response.request_id
        );

        Ok(())
    }

    fn forward_to_servers(server_urls: &[String], request: ClientRequest) -> MiddlewareResponse {
        match request {
            //VIEWS NEED TO CHANGE
            ClientRequest::EncryptImage {
                request_id,
                image_path,
                views,
            } => {
                // Forward encryption to ALL servers and wait for first response
                //VIEWS NEED TO CHANGE
                Self::send_encrypt_to_multiple_servers(server_urls, request_id, &image_path, views)
            }
            ClientRequest::DecryptImage {
                request_id,
                image_path,
                username,
            } => {
                // Handle decryption locally (no server needed)
                Self::decrypt_image_locally(request_id, &image_path,&username)
            }
        }
    }
    /// Send encryption request to ALL servers simultaneously
    /// Returns the FIRST successful response
    fn send_encrypt_to_multiple_servers(
        server_urls: &[String],
        request_id: u64,
        image_path: &str,
        views: HashMap<String, u64>, //VIEWS NEED TO CHANGE
    ) -> MiddlewareResponse {
        use std::fs;
        use std::path::Path;

        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Image file not found");
        }

        // Read file once (shared by all threads)
        let file_data = match fs::read(image_path) {
            Ok(data) => data,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to read file: {}", e),
                );
            }
        };

        let filename = Path::new(image_path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // === NEW: compute timeout based on image size ===
        // Base timeout: 30 seconds
        // Per-MB overhead: 6 seconds per MB (ceiling)
        let size_bytes = file_data.len() as f64;
        let size_mb = size_bytes / (1024.0 * 1024.0);
        let per_mb_secs: u64 = 15;
        let extra_mb = size_mb.ceil() as u64; // ceil(3.5) -> 4
        let timeout_secs = 30u64.saturating_add(extra_mb.saturating_mul(per_mb_secs));
        let timeout_duration = Duration::from_secs(timeout_secs);
        println!(
            "[ClientMiddleware] [Req #{}] Computed timeout: {} seconds (size: {:.2} MB → +{} MB * {}s/MB)",
            request_id, timeout_secs, size_mb, extra_mb, per_mb_secs
        );
        // ===============================================

        println!(
            "[ClientMiddleware] [Req #{}] Broadcasting to {} servers ({} bytes) ({:?} views) -> timeout: {}s",
            request_id,
            server_urls.len(),
            file_data.len(),
            views, //VIEWS NEED TO CHANGE
            timeout_secs
        );

        // Keep retrying until success
        loop {
            let start_time = Instant::now();
            let response: Arc<Mutex<Option<MiddlewareResponse>>> = Arc::new(Mutex::new(None));
            let mut handles = vec![];

            // Launch parallel requests to all servers
            for (index, server_url) in server_urls.iter().enumerate() {
                let server_url = server_url.clone();
                let file_data = file_data.clone();
                let filename = filename.clone();
                let response = Arc::clone(&response);
                let views = views.clone(); //VIEWS NEED TO CHANGE

                let handle = thread::spawn(move || {
                    println!(
                        "[ClientMiddleware] [Req #{}] [Server {}] Sending to {} ({:?} views)",
                        request_id,
                        index + 1,
                        server_url,
                        views //VIEWS NEED TO CHANGE
                    );

                    match Self::send_encrypt_to_single_server(
                        &server_url,
                        request_id,
                        &filename,
                        &file_data,
                        &views, //VIEWS NEED TO CHANGE
                    ) {
                        Ok(server_response) => {
                            if server_response.status == "OK" {
                                let mut response_lock = response.lock().unwrap();
                                if response_lock.is_none() {
                                    println!(
                                        "[ClientMiddleware] [Req #{}] [Server {}] FIRST OK RESPONSE (Winner!)",
                                        request_id,
                                        index + 1
                                    );
                                    *response_lock = Some(server_response);
                                } else {
                                    println!(
                                        "[ClientMiddleware] [Req #{}] [Server {}] OK (but too late)",
                                        request_id,
                                        index + 1
                                    );
                                }
                            } else {
                                println!(
                                    "[ClientMiddleware] [Req #{}] [Server {}] Response not OK",
                                    request_id,
                                    index + 1
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[ClientMiddleware] [Req #{}] [Server {}] Failed: {}",
                                request_id,
                                index + 1,
                                e
                            );
                        }
                    }
                });

                handles.push(handle);
            }

            // Wait for threads or computed timeout
            while start_time.elapsed() < timeout_duration {
                {
                    let response_lock = response.lock().unwrap();
                    if let Some(resp) = response_lock.as_ref() {
                        println!(
                            "[ClientMiddleware] [Req #{}] Broadcasting complete - got response!",
                            request_id
                        );
                        return resp.clone();
                    }
                }
                thread::sleep(Duration::from_millis(500)); // check every 0.5s
            }

            // Timeout: no OK response
            println!(
                "[ClientMiddleware] [Req #{}] Timeout after {}s - retrying broadcast...",
                request_id, timeout_secs
            );

            // Make sure all threads finish cleanly before retry
            for handle in handles {
                let _ = handle.join();
            }

            // Wait briefly before retrying (optional)
            thread::sleep(Duration::from_secs(2));
        }
    }

    fn send_encrypt_to_single_server( 
        server_url: &str,
        request_id: u64,
        filename: &str,
        file_data: &[u8],
        views: HashMap<String, u64>,//VIEWS NEED TO CHANGE
    ) -> Result<MiddlewareResponse, Box<dyn Error>> {
        // === NEW: compute client timeout consistently with outer logic ===
        let size_bytes = file_data.len() as f64;
        let size_mb = size_bytes / (1024.0 * 1024.0);
        let per_mb_secs: u64 = 15;
        let extra_mb = size_mb.ceil() as u64;
        let timeout_secs = 30u64.saturating_add(extra_mb.saturating_mul(per_mb_secs));
        // ===============================================================

        // Create multipart form using reqwest blocking client
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_secs)) // use computed timeout
            .build()?;

        let url = format!("{}/encrypt", server_url);
        let views_json = serde_json::to_string(&views)?; //NEED TO SERIALIZE FIRST, DESERIALIZE SERVER SIDE
        let form = reqwest::blocking::multipart::Form::new()
            .text("request_id", request_id.to_string())
            .text("filename", filename.to_string())
            .text("views", views_json) //VIEWS NEED TO CHANGE
            .part(
                "file",
                reqwest::blocking::multipart::Part::bytes(file_data.to_vec())
                    .file_name(filename.to_string()),
            );

        // Send HTTP POST request
        let response = client.post(&url).multipart(form).send()?;

        // Parse response
        let server_resp: ServerResponse = response.json()?;

        if server_resp.status == "success" {
            // Save returned file if present
            if let (Some(file_data_b64), Some(output_filename)) =
                (&server_resp.file_data, &server_resp.output_filename)
            {
                let file_data = general_purpose::STANDARD.decode(file_data_b64)?;
                let output_dir = "client_storage";
                std::fs::create_dir_all(output_dir)?; // ensure dir exists
                let output_stem = Path::new(output_filename)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("output");
                let output_path = format!("{}/{}.png", output_dir, output_stem);
                //let output_path = format!("{}/{}", output_dir, output_filename);
                std::fs::write(&output_path, file_data)?;

                return Ok(MiddlewareResponse::success(
                    request_id,
                    &server_resp.message,
                    Some(output_path.to_string()),
                ));
            }

            Ok(MiddlewareResponse::success(
                request_id,
                &server_resp.message,
                server_resp.output_filename.clone(),
            ))
        } else {
            Err(format!("Server returned error: {}", server_resp.message).into())
        }
    }

    // New local decryption function (dummy implementation)
    fn decrypt_image_locally(request_id: u64, image_path: &str, username: &str) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Encrypted file not found");
        }

        println!(
            "[ClientMiddleware] [Req #{}] Decrypting locally: {}",
            request_id, image_path
        );

        //DECRYPTION LOGIC NEEDED
        //EXTRACT VIEWS LIST
        let decoder = Decoder::new(File::open(image_path));
        let mut reader = decoder.read_info();
        let mut encrypted = None;
        for chunk in reader.info().uncompressed_latin1_text.iter() {
            if chunk.keyword == "EncryptedViews" {
                encrypted = Some(chunk.text.clone());
            }
        }
        for chunk in reader.info().utf8_text.iter() {
            if chunk.keyword == "EncryptedViews" {
                encrypted = Some(chunk.text.clone());
            }
        }
        for chunk in reader.info().compressed_latin1_text.iter() {
            if chunk.keyword == "EncryptedViews" {
                encrypted = Some(chunk.text.clone());
            }
        }
        let encrypted = encrypted.ok_or("EncryptedViews chunk not found");
        let secret_key = b"supersecretkey_supersecretkey_32";
        let view_key = Key::<XChaCha20Poly1305>::from_slice(secret_key);
        let cipher = XChaCha20Poly1305::new(&view_key);

        let decoded_views = hex::decode(encrypted);
        let (nonce_bytes, ciphertext) = decoded_views.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] });
        //VIEWS EXTRACTED
        let parsed_views: HashMap<String, u64> = serde_json::from_slice(&plaintext);
        println!(
            "[ClientMiddleware] [Req #{}] Image Users and Views: {:?}",
            request_id, parsed_views
        );
        //CHECK IF WE CAN STILL VIEW (AGREE ON IMPLEMENTATION LATER)
        if let Some(count) = parsed_views.get(username) {
            if *count == 0 {
                return Ok(MiddlewareResponse::error(request_id, "Username Views Exceeded"));
            }
            *count -= 1;
            // User exists and has views
            println!("User {} has {} views remaining", username, *count);
        } else {
            // Username not found
            return Ok(MiddlewareResponse::error(request_id, "Username Not Found"));
        }
        
        //DECREMENT VIEW COUNT IF ALLOWED
        //RETURN ERROR IF NOT ALLOWED
        //CHANGE PAYLOAD TO REFLECT NEW VIEW COUNT
        let tmp_extract_dir = match tempfile::tempdir_in("/tmp") {
            Ok(dir) => dir,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to create temp folder: {}", e),
                );
            }
        };
        println!(
            "Temporary extraction folder: {}",
            tmp_extract_dir.path().display()
        );

        println!("[ClientMiddleware] [Req #{}] Decryption Begin", request_id);

        
        //let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(secret_key);

        //VIEW ENCRYPTION SETUP
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        //VIEW ENCRYPTION LOGIC
        let json = serde_json::to_vec(&parsed_views);
        let ciphertext = cipher.encrypt(nonce, Payload { msg: &json, aad: &[] });
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&ciphertext);
        let encoded_views=hex::encode(full);
        
        
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
        let extracted_file_path = match fs::read_dir(tmp_extract_dir.path()).and_then(|mut rd| {
            rd.next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "No extracted file found")
                })?
                .map(|e| e.path())
        }) {
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
        println!(
            "First 32 bytes: {:?}",
            &extracted_bytes[..32.min(extracted_bytes.len())]
        );

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
        // if let Some(extra) = &recovered.extra {
        //     println!("Extra: {}", extra);
        // }
        let output_dir = PathBuf::from("client_storage");
        if let Err(e) = std::fs::create_dir_all(&output_dir) {
            return MiddlewareResponse::error(
                request_id,
                &format!("Failed to create directory: {}", e),
            );
        }

        //fs::create_dir_all(&output_dir)?;
        let output_stem = Path::new(image_path)
            .file_stem() // e.g. "encrypted_input"
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let output_path = output_dir.join(format!("decrypted_{}.png", output_stem));
        match fs::write(&output_path, &recovered.image_bytes) {
            Ok(_) => {
                println!(
                    "[ClientMiddleware] [Req #{}] Decryption complete → saved hidden image as: {}",
                    request_id,
                    output_path.display()
                );
                //EMBED UPDATED VIEWS INTO IMAGE
                let file = File::open(output_path);
                let decoder = Decoder::new(BufReader::new(file));
                let mut reader = decoder.read_info();
                let mut buf = vec![0; reader.output_buffer_size()];
                let info = reader.next_frame(&mut buf);
                buf.truncate(info.buffer_size());

                // Re-encode with a new iTXt chunk
                let out = File::create(output_path);
                let w = BufWriter::new(out);

                let mut encoder = Encoder::new(w, info.width, info.height);
                encoder.set_color(info.color_type);
                encoder.set_depth(info.bit_depth);

                let mut writer = encoder.write_header();

                writer.write_text_chunk(TextChunk::InternationalText {
                    keyword: "EncryptedViews".into(),
                    language_tag: "".into(),
                    translated_keyword: "".into(),
                    text: encoded_views.into(),
                    compressed: false,
                });

                writer.write_image_data(&buf);
                writer.finish();
                MiddlewareResponse::success(
                    request_id,
                    &format!(
                        "Image successfully decrypted and saved to {}",
                        output_path.display()
                    ),
                    Some(output_path.to_string_lossy().to_string()),
                )
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to save decrypted image: {}",
                    request_id, e
                );
                MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to save decrypted image: {}", e),
                )
            }
        }
    }
}
