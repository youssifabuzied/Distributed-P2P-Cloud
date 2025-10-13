// =======================================
// server_middleware.rs
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Responsibilities:
// - Listen for HTTP requests from client middlewares (Port 8000)
// - Process image encryption/decryption requests
// - Communicate with other server middlewares (Port 8001 - Future)
//
// Cargo.toml dependencies needed:
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// axum = "0.7"
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// tower = "0.4"
// tower-http = { version = "0.5", features = ["fs", "trace"] }

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::fs;
use tower_http::trace::TraceLayer;

// =======================================
// Data Structures
// =======================================

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageRequest {
    pub request_id: u64,
    pub operation: String, // "encrypt" or "decrypt"
    pub filename: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageResponse {
    pub request_id: u64,
    pub status: String,
    pub message: String,
    pub output_filename: Option<String>,
}

impl ImageResponse {
    pub fn success(request_id: u64, message: &str, output_filename: String) -> Self {
        ImageResponse {
            request_id,
            status: "OK".to_string(),
            message: message.to_string(),
            output_filename: Some(output_filename),
        }
    }

    pub fn error(request_id: u64, message: &str) -> Self {
        ImageResponse {
            request_id,
            status: "ERROR".to_string(),
            message: message.to_string(),
            output_filename: None,
        }
    }
}

// =======================================
// Application State
// =======================================

#[derive(Clone)]
pub struct AppState {
    pub storage_path: String,
}

impl AppState {
    pub fn new(storage_path: &str) -> Self {
        AppState {
            storage_path: storage_path.to_string(),
        }
    }
}

// =======================================
// Server Middleware
// =======================================

pub struct ServerMiddleware {
    pub client_port: u16,      // Port for client middleware communication
    pub server_port: u16,      // Port for server-to-server communication (future)
    pub storage_path: String,  // Where to store images
}

impl ServerMiddleware {
    pub fn new(client_port: u16, server_port: u16, storage_path: &str) -> Self {
        ServerMiddleware {
            client_port,
            server_port,
            storage_path: storage_path.to_string(),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&self.storage_path).await?;

        println!("========================================");
        println!("Cloud P2P Server Middleware");
        println!("========================================");
        println!("[Server] Storage path: {}", self.storage_path);
        println!("[Server] Client middleware port: {}", self.client_port);
        println!("[Server] Server-to-server port: {} (reserved for future)", self.server_port);
        println!("========================================\n");

        // Create application state
        let state = Arc::new(AppState::new(&self.storage_path));

        // Build router for client middleware communication
        let app = Router::new()
            .route("/", get(root_handler))
            .route("/health", get(health_handler))
            .route("/upload", post(upload_handler))
            .route("/encrypt", post(encrypt_handler))
            .route("/decrypt", post(decrypt_handler))
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        // Start server
        let addr = format!("0.0.0.0:{}", self.client_port);
        println!("[Server] Starting client middleware listener on {}", addr);
        println!("[Server] Ready to accept requests!\n");

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

// =======================================
// HTTP Handlers - Client Middleware API
// =======================================

/// Root endpoint
async fn root_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "Cloud P2P Server Middleware",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "upload": "/upload (POST multipart/form-data)",
            "encrypt": "/encrypt (POST multipart/form-data)",
            "decrypt": "/decrypt (POST multipart/form-data)"
        }
    }))
}

/// Health check endpoint
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Upload image endpoint
async fn upload_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<ImageResponse>, StatusCode> {
    println!("[Server] Received upload request");

    let mut request_id = 0u64;
    let mut filename = String::new();
    let mut file_data: Vec<u8> = Vec::new();

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "request_id" => {
                let data = field.text().await.unwrap();
                request_id = data.parse().unwrap_or(0);
            }
            "filename" => {
                filename = field.text().await.unwrap();
            }
            "file" => {
                file_data = field.bytes().await.unwrap().to_vec();
            }
            _ => {}
        }
    }

    if filename.is_empty() || file_data.is_empty() {
        eprintln!("[Server] Missing filename or file data");
        return Ok(Json(ImageResponse::error(request_id, "Missing filename or file data")));
    }

    // Save file to storage
    let file_path = format!("{}/{}", state.storage_path, filename);
    
    match fs::write(&file_path, &file_data).await {
        Ok(_) => {
            println!("[Server] [Req #{}] Saved file: {} ({} bytes)", 
                     request_id, filename, file_data.len());
            
            Ok(Json(ImageResponse::success(
                request_id,
                "File uploaded successfully",
                filename,
            )))
        }
        Err(e) => {
            eprintln!("[Server] [Req #{}] Failed to save file: {}", request_id, e);
            Ok(Json(ImageResponse::error(request_id, &format!("Failed to save file: {}", e))))
        }
    }
}

/// Encrypt image endpoint
async fn encrypt_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    println!("[Server] Received encrypt request");

    let mut request_id = 0u64;
    let mut filename = String::new();
    let mut file_data: Vec<u8> = Vec::new();

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "request_id" => {
                let data = field.text().await.unwrap();
                request_id = data.parse().unwrap_or(0);
            }
            "filename" => {
                filename = field.text().await.unwrap();
            }
            "file" => {
                file_data = field.bytes().await.unwrap().to_vec();
            }
            _ => {}
        }
    }

    if filename.is_empty() || file_data.is_empty() {
        return Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "ERROR",
            "message": "Missing filename or file data"
        })));
    }

    println!("[Server] [Req #{}] Forwarding encryption request to server: {} ({} bytes)", request_id, filename, file_data.len());

    // Build EncryptionRequest
    let encryption_request = serde_json::json!({
        "request_id": request_id,
        "filename": filename,
        "file_data": file_data,
    });

    // Send request to server (TCP, port 7000)
    let server_addr = "127.0.0.1:7000";
    match tokio::task::spawn_blocking(move || {
        use std::net::TcpStream;
        use std::io::{Write, BufRead, BufReader};
        let mut stream = match TcpStream::connect(server_addr) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to connect to server: {}", e)),
        };
        let req_str = serde_json::to_string(&encryption_request).unwrap();
        if let Err(e) = stream.write_all(req_str.as_bytes()) {
            return Err(format!("Failed to send request: {}", e));
        }
        if let Err(e) = stream.write_all(b"\n") {
            return Err(format!("Failed to send newline: {}", e));
        }
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        if let Err(e) = reader.read_line(&mut response_line) {
            return Err(format!("Failed to read response: {}", e));
        }
        Ok(response_line)
    }).await {
        Ok(Ok(response_line)) => {
            // Parse EncryptionResponse
            match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                Ok(resp_json) => {
                    let status = resp_json["status"].as_str().unwrap_or("ERROR");
                    let message = resp_json["message"].as_str().unwrap_or("");
                    let output_filename = format!("{}.encrypted", filename);
                    let encrypted_data = resp_json["encrypted_data"].as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|b| b as u8)).collect::<Vec<u8>>())
                        .unwrap_or_default();
                    let base64_data = base64_helper::encode(&encrypted_data);
                    Ok(Json(serde_json::json!({
                        "request_id": request_id,
                        "status": status,
                        "message": message,
                        "output_filename": output_filename,
                        "file_data": base64_data,
                        "file_size": encrypted_data.len()
                    })))
                }
                Err(e) => {
                    eprintln!("[Server] [Req #{}] Failed to parse server response: {}", request_id, e);
                    Ok(Json(serde_json::json!({
                        "request_id": request_id,
                        "status": "ERROR",
                        "message": format!("Failed to parse server response: {}", e)
                    })))
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!("[Server] [Req #{}] Server communication error: {}", request_id, e);
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": format!("Server communication error: {}", e)
            })))
        }
        Err(e) => {
            eprintln!("[Server] [Req #{}] Server communication error: {}", request_id, e);
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": format!("Server communication error: {}", e.to_string())
            })))
        }
    }
}

/// Decrypt image endpoint
async fn decrypt_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    println!("[Server] Received decrypt request");

    let mut request_id = 0u64;
    let mut filename = String::new();
    let mut file_data: Vec<u8> = Vec::new();

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "request_id" => {
                let data = field.text().await.unwrap();
                request_id = data.parse().unwrap_or(0);
            }
            "filename" => {
                filename = field.text().await.unwrap();
            }
            "file" => {
                file_data = field.bytes().await.unwrap().to_vec();
            }
            _ => {}
        }
    }

    if filename.is_empty() || file_data.is_empty() {
        return Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "ERROR",
            "message": "Missing filename or file data"
        })));
    }

    println!("[Server] [Req #{}] Decrypting: {} ({} bytes)", 
             request_id, filename, file_data.len());

    // TODO: Implement actual decryption
    // For now, just return the same image data (as requested)
    let decrypted_data = file_data.clone();
    
    let output_filename = if filename.ends_with(".encrypted") {
        filename.strip_suffix(".encrypted").unwrap().to_string()
    } else {
        format!("{}.decrypted", filename)
    };

    // Save decrypted file
    let output_path = format!("{}/{}", state.storage_path, output_filename);
    match fs::write(&output_path, &decrypted_data).await {
        Ok(_) => {
            println!("[Server] [Req #{}] Decryption complete: {}", request_id, output_filename);
            
            // Encode file as base64 for JSON response
            let base64_data = base64_helper::encode(&decrypted_data);
            
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "OK",
                "message": "Image decrypted successfully",
                "output_filename": output_filename,
                "file_data": base64_data,
                "file_size": decrypted_data.len()
            })))
        }
        Err(e) => {
            eprintln!("[Server] [Req #{}] Failed to save decrypted file: {}", request_id, e);
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": format!("Failed to save decrypted file: {}", e)
            })))
        }
    }
}

// =======================================
// Server-to-Server Communication
// =======================================
// Port 8001 is reserved for future server-to-server communication
// This will be implemented later for P2P server synchronization

// =======================================
// Main Entry Point
// =======================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let server = ServerMiddleware::new(
        8000,                    // Client middleware port
        8001,                    // Server-to-server port (future)
        "./server_storage"       // Storage directory
    );

    server.start().await?;

    Ok(())
}

// Add base64 dependency
// Base64 helper functions
mod base64_helper {
    pub fn encode(data: &[u8]) -> String {
        base64::encode(data)
    }
    
    pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode(data)
    }
}
// Add chrono for timestamps
mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }
    
    pub struct DateTime;
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            // Simple timestamp
            format!("{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs())
        }
    }
}