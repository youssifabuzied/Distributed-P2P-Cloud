// =======================================
// server.rs - Deterministic required-side cover selection (no retries)
// Cloud P2P Controlled Image Sharing Project
// =======================================

use bincode;
use hex;
use image::imageops::FilterType;
use image::io::Reader as ImageReader;
use image::{DynamicImage, GenericImageView, ImageFormat};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::{BufRead, Cursor, Write, BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use tempfile::Builder;
use std::collections::HashMap;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce, Key
};
use png::{Encoder, Decoder};
use png::text_metadata::{ITXtChunk};
use std::fs::File;
// Re-import the steganography builder function used in original code
use stegano_core::api::hide::prepare as hide_prepare;

// Import middleware module and its config types
mod middleware;
use middleware::{PeerInfo, ServerConfig, ServerMiddleware};

// =======================================
// Data Structures
// =======================================

/// Request structure for encryption operations
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionRequest { //VIEWS NEED TO CHANGE
    pub request_id: u64,
    pub filename: String,
    pub views: HashMap<String, u64>,
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
struct HiddenPayload { //VIEWS NEED TO CHANGE
    message: String,
    //views: u64,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    //extra: Option<String>,
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

// Cached cover metadata to support dynamic selection
#[derive(Clone)]
struct CachedCover {
    name: String,
    dyn_image: Arc<DynamicImage>,
    png_bytes: Arc<Vec<u8>>,
    width: u32,
    height: u32,
    capacity: f32,
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
    ///
    /// This method preloads and caches multiple cover images of
    /// different sizes and picks the best one per-request for fastest
    /// resizing/encoding.
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;

        println!("========================================");
        println!("Cloud P2P Server (Internal Encryption)");
        println!("========================================");
        println!("[Server] Listening on {}", addr);
        println!("[Server] Ready to process encryption requests...\n");

        // Ensure /tmp exists once (safe optimization)
        let tmp_dir = PathBuf::from("/tmp");
        if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
            eprintln!("[Server] Failed to ensure /tmp exists: {}", e);
            // continue; operations will fail later if /tmp truly unusable
        }

        // --- Preload multiple cover images (small, medium, large) ---
        let cover_paths = vec![
            (
                "small",
                PathBuf::from("resources/default/default_image_small.png"),
            ),
            (
                "medium",
                PathBuf::from("resources/default/default_image_medium.png"),
            ),
            (
                "large",
                PathBuf::from("resources/default/default_image_large.png"),
            ),
            // (
            //     "extra_large",
            //     PathBuf::from("resources/default/default_image_extra_large.png"),
            // ),
        ];

        let mut covers: Vec<CachedCover> = Vec::new();

        for (name, path) in cover_paths.into_iter() {
            match ImageReader::open(&path) {
                Ok(reader) => match reader.decode() {
                    Ok(img) => {
                        // encode PNG bytes once
                        let mut png_buf = Vec::new();
                        if let Err(e) =
                            img.write_to(&mut Cursor::new(&mut png_buf), ImageFormat::Png)
                        {
                            eprintln!(
                                "[Server] Failed to encode cover {} to PNG: {}",
                                path.display(),
                                e
                            );
                            return Err(Box::new(e));
                        }
                        let (w, h) = img.dimensions();
                        let capacity = (w as f32 * h as f32) * 0.375f32; // same heuristic used later

                        covers.push(CachedCover {
                            name: name.to_string(),
                            dyn_image: Arc::new(img),
                            png_bytes: Arc::new(png_buf),
                            width: w,
                            height: h,
                            capacity,
                        });

                        println!(
                            "[Server] Loaded cover '{}' ({}x{}, capacity {:.0} bytes)",
                            name, w, h, capacity
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[Server] Failed to decode cover image at startup: {}: {}",
                            path.display(),
                            e
                        );
                        return Err(Box::new(e));
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[Server] Failed to open cover image at startup: {}: {}",
                        path.display(),
                        e
                    );
                    return Err(Box::new(e));
                }
            }
        }

        // Wrap covers in Arc so we can clone cheaply into the per-connection threads
        let covers_arc = Arc::new(covers);

        // Cache password_hex once (safe optimization)
        let secret_key: &[u8] = b"supersecretkey_supersecretkey_32";
        let view_key = Key::<XChaCha20Poly1305>::from_slice(secret_key);
        let password_hex = Arc::new(hex::encode(view_key));

        // Accept incoming connections
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    println!("[Server] New connection from: {}", peer_addr);

                    // Clone cached resources to move into thread
                    let tmp_dir_clone = tmp_dir.clone();
                    let covers_clone = Arc::clone(&covers_arc);
                    let password_hex_clone = Arc::clone(&password_hex);

                    // Spawn new thread for processing
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_request(
                            stream,
                            &tmp_dir_clone,
                            covers_clone,
                            password_hex_clone,
                        ) {
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
    #[allow(clippy::too_many_arguments)]
    fn handle_request(
        stream: TcpStream,
        tmp_dir: &PathBuf,
        covers: Arc<Vec<CachedCover>>,
        password_hex: Arc<String>,
    ) -> Result<(), Box<dyn Error>> {
        // Read until newline into a buffer (avoids extra String allocation)
        let mut read_buf: Vec<u8> = Vec::new();
        let mut reader = std::io::BufReader::new(&stream);
        let bytes_read = reader.read_until(b'\n', &mut read_buf)?;
        if bytes_read == 0 {
            // nothing read; connection closed
            return Ok(());
        }

        // Trim trailing newline/carriage returns
        while read_buf.last().map(|b| *b == b'\n' || *b == b'\r') == Some(true) {
            read_buf.pop();
        }

        if read_buf.is_empty() {
            return Ok(());
        }

        println!("[Server] Received request: {} bytes", read_buf.len());

        // Parse request directly from bytes to avoid extra copies
        let response = match serde_json::from_slice::<EncryptionRequest>(&read_buf) {
            Ok(request) => {
                println!(
                    "[Server] [Req #{}] Processing encryption for: {} ({} bytes) (views: {})",
                    request.request_id,
                    request.filename,
                    request.file_data.len(),
                    request.views //VIEWS NEED TO CHANGE
                );

                // Proceed to encryption with cached resources
                Self::encrypt_data(request, tmp_dir, &covers, &password_hex)
            }
            Err(e) => {
                eprintln!("[Server] Invalid request format: {}", e);
                EncryptionResponse::error(0, "Invalid request format")
            }
        };

        // Send response back (JSON line)
        let mut writer = &stream;
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
    ///
    /// Chooses the most appropriate cached cover image (small/medium/large) so that
    /// resizing work is minimized and overall latency is reduced. This version
    /// computes a conservative required_side up-front (no retries).
    fn encrypt_data( 
        request: EncryptionRequest,
        tmp_dir: &PathBuf,
        covers: &Arc<Vec<CachedCover>>,
        password_hex: &Arc<String>,
    ) -> EncryptionResponse {
        println!(
            "[Server] [Req #{}] Starting encryption: {} ({} bytes) (views: {})",
            request.request_id,
            request.filename,
            request.file_data.len(),
            request.views //VIEWS NEED TO CHANGE
        );

        // original_size to return in responses
        let original_size = request.file_data.len();

        // Determine file extension
        let ext = std::path::Path::new(&request.filename)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Convert uploaded JPEG to PNG in-memory when necessary (no tmp file)
        let mut working_image_bytes = request.file_data.clone();
        if ext == "jpg" || ext == "jpeg" {
            println!(
                "[Server] [Req #{}] JPEG detected — converting to PNG in-memory...",
                request.request_id
            );

            match image::load_from_memory(&request.file_data) {
                Ok(img) => {
                    let mut png_buf = Vec::with_capacity(request.file_data.len().saturating_mul(2));
                    if let Err(e) = img.write_to(&mut Cursor::new(&mut png_buf), ImageFormat::Png) {
                        eprintln!(
                            "[Server] [Req #{}] Failed to encode uploaded JPEG to PNG: {}",
                            request.request_id, e
                        );
                        return EncryptionResponse {
                            request_id: request.request_id,
                            status: "error".into(),
                            message: format!("Failed to encode uploaded JPEG to PNG: {}", e),
                            encrypted_data: None,
                            original_size,
                            encrypted_size: 0,
                        };
                    }
                    working_image_bytes = png_buf;
                }
                Err(e) => {
                    eprintln!(
                        "[Server] [Req #{}] Failed to decode uploaded JPEG from memory: {}",
                        request.request_id, e
                    );
                    return EncryptionResponse {
                        request_id: request.request_id,
                        status: "error".into(),
                        message: format!("Failed to decode uploaded JPEG: {}", e),
                        encrypted_data: None,
                        original_size,
                        encrypted_size: 0,
                    };
                }
            }
        }


        //VIEW ENCRYPTION SETUP
        let view_key = Key::from_slice(secret_key);
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let json = serde_json::to_vec(&ViewsData { views: views.clone() })?;
        //VIEW ENCRYPTION LOGIC
        let ciphertext = cipher.encrypt(nonce, Payload { msg: &json, aad: &[] })?;
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&ciphertext);
        let encoded_views=hex::encode(full);
        //VIEW DECODING LOGIC
        let decoded_views = hex::decode(encoded_views)?
        let (nonce_bytes, ciphertext) = decoded_views.split_at(12);
        let plaintext = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] })?;
        let parsed: ViewsData = serde_json::from_slice(&plaintext)?;
        let parsed_views = parsed.views;

        // Build payload and serialize with bincode
        let payload = HiddenPayload {
            message: format!("Hidden from file: {}", request.filename),
            views: request.views, //VIEWS NEED TO CHANGE
            image_bytes: working_image_bytes.clone(),
            extra: Some("Metadata info".to_string()),
        };
        //NEED TO CHANGE ENCRYPTION LOGIC
        //VIEWS TO BE ENCODED OUTSIDE OF COVER IMAGE
        //MODFIY FUNCTION TO REFLECT THIS
        let serialized = match bincode::serialize(&payload) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[Server] Serialization failed: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to serialize payload: {}", e),
                    encrypted_data: None,
                    original_size,
                    encrypted_size: 0,
                };
            }
        };

        println!(
            "[Server] [Req #{}] Serialized payload: {} bytes (views: {})",
            request.request_id,
            serialized.len(),
            request.views
        );

        // ------------------------------
        // Deterministic required-side logic
        // ------------------------------
        // Constants to tweak: header overhead and pixel margin (small)
        const BYTES_PER_PIXEL: f32 = 0.375_f32; // heuristic used previously
        const HEADER_OVERHEAD: usize = 1024; // conservative estimate for stegano headers (tweak if needed)
        const MARGIN_PIXELS: u32 = 2; // safety margin in pixels

        let payload_len = serialized.len();
        let required_pixels = ((payload_len + HEADER_OVERHEAD) as f32 / BYTES_PER_PIXEL).ceil();
        let mut required_side = (required_pixels.sqrt()).ceil() as u32;
        required_side = required_side.saturating_add(MARGIN_PIXELS);

        // Choose best cover by minimizing uniform scale factor to meet required_side
        let mut best_index: Option<usize> = None;
        let mut best_scale: f32 = f32::MAX;

        for (i, c) in covers.iter().enumerate() {
            let w = c.width as f32;
            let h = c.height as f32;

            let scale_w = (required_side as f32) / w;
            let scale_h = (required_side as f32) / h;
            let scale = scale_w.max(scale_h).max(1.0);

            // small bias: if scale is very close to 1, prefer slightly larger covers to avoid tiny encodes
            let adjusted_scale = if (scale - 1.0).abs() < 0.05 {
                // bias factor reduces effective scale for larger images (heuristic)
                let area = (c.width as f32) * (c.height as f32);
                scale * (1.0 - (area / (10_000_000.0)).min(0.02)) // tiny bias
            } else {
                scale
            };

            if adjusted_scale < best_scale {
                best_scale = adjusted_scale;
                best_index = Some(i);
            }
        }

        let chosen = match best_index {
            Some(i) => &covers[i],
            None => &covers[0],
        };

        println!(
            "[Server] [Req #{}] Chosen cover '{}' ({}x{}, capacity {:.0}), required_side {}, scale {:.4}",
            request.request_id,
            chosen.name,
            chosen.width,
            chosen.height,
            chosen.capacity,
            required_side,
            best_scale
        );

        // Compute final target dimensions and ensure they meet required_side
        let mut target_w = ((chosen.width as f32) * best_scale).ceil() as u32;
        let mut target_h = ((chosen.height as f32) * best_scale).ceil() as u32;
        if target_w < required_side {
            target_w = required_side;
        }
        if target_h < required_side {
            target_h = required_side;
        }
        // final tiny safety margin
        target_w = target_w.saturating_add(1);
        target_h = target_h.saturating_add(1);

        // Reuse cached PNG bytes when no resize required
        let mut cover_buf: Vec<u8> = if best_scale <= 1.0 + f32::EPSILON {
            // reuse cached encoded PNG
            chosen.png_bytes.as_ref().clone()
        } else {
            // Resize chosen cover once and encode to PNG buffer
            let filter = if best_scale > 2.0 {
                FilterType::Triangle
            } else {
                FilterType::Lanczos3
            };
            println!(
                "[Server] [Req #{}] Resizing chosen cover '{}' {}x{} -> {}x{} (scale {:.4}) using {:?}",
                request.request_id,
                chosen.name,
                chosen.width,
                chosen.height,
                target_w,
                target_h,
                best_scale,
                filter
            );
            let resized = chosen.dyn_image.resize(target_w, target_h, filter);
            let mut buf = Vec::new();
            if let Err(e) = resized.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png) {
                eprintln!("[Server] Failed to encode resized cover: {}", e);
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to encode resized cover image: {}", e),
                    encrypted_data: None,
                    original_size,
                    encrypted_size: 0,
                };
            }
            buf
        };

        // Write serialized payload and cover to temporary files under /tmp (deterministic names)
        let payload_path = tmp_dir.join(format!("payload_{}.bin", request.request_id));
        let cover_path = tmp_dir.join(format!("cover_{}.png", request.request_id));
        let output_path = tmp_dir.join(format!("stego_{}.png", request.request_id));

        if let Err(e) = fs::write(&payload_path, &serialized) {
            eprintln!("[Server] Failed to write payload file: {}", e);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to write payload file: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }

        if let Err(e) = fs::write(&cover_path, &cover_buf) {
            eprintln!("[Server] Failed to write cover file: {}", e);
            let _ = fs::remove_file(&payload_path);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to write cover file: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }

        // Steganography invocation (same as original). Use cached hex password.
        println!(
            "[Server] [Req #{}] Executing steganography...",
            request.request_id
        );

        if let Err(e) = hide_prepare()
            .with_file(&payload_path)
            .with_image(&cover_path)
            .with_output(&output_path)
            .using_password(password_hex.as_str())
            .execute()
        {
            eprintln!("[Server] Steganography execution failed: {}", e);
            let _ = fs::remove_file(&payload_path);
            let _ = fs::remove_file(&cover_path);
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Steganography failed: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }

        // Read stego output
        let stego_bytes = match fs::read(&output_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[Server] Failed to read stego output: {}", e);
                let _ = fs::remove_file(&payload_path);
                let _ = fs::remove_file(&cover_path);
                let _ = fs::remove_file(&output_path);
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

        // Best-effort cleanup of temp files
        let _ = fs::remove_file(&payload_path);
        let _ = fs::remove_file(&cover_path);
        let _ = fs::remove_file(&output_path);

        println!(
            "[Server] [Req #{}] ✓ Encryption complete: {} bytes -> {} bytes (views: {})",
            request.request_id,
            original_size,
            stego_bytes.len(),
            request.views
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

    // Server configuration (unchanged defaults, only example)
    let config = ServerConfig {
        server_id: 2,               // ← Unique server ID
        priority: 20,               // ← Election priority (higher wins)
        client_port: 8000,          // ← HTTP port for client middleware
        peer_port: 8001,            // ← HTTP port for peer election
        internal_server_port: 7000, // ← TCP port for encryption server
        peers: vec![
            // PeerInfo {
            //     server_id: 1,
            //     address: "10.251.174.138:8001".to_string(),
            // },
            // PeerInfo {
            //     server_id: 3,
            //     address: "10.251.174.183:8001".to_string(),
            // },
        ],
        election_timeout_ms: 3500,
        failure_port: 8002,
        failure_check_interval_secs: 10,
        recovery_timeout_secs: 10,
        enable_failure_simulation: false,
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

    // Small sleep to allow TCP server to boot
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Start async ServerMiddleware with election support
    let server_middleware = ServerMiddleware::new(config);
    server_middleware.start().await?;

    // Join internal server thread (blocks indefinitely)
    let _ = server_handle.join();

    Ok(())
}
