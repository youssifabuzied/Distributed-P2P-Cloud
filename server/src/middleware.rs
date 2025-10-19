// =======================================
// middleware.rs - Simplified Election
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Election Algorithm:
// 1. Each server broadcasts its priority to all peers (no response expected)
// 2. Each server listens for 5 seconds for higher priority announcements
// 3. If higher priority received -> drop request
// 4. If no higher priority after 5 seconds -> process request

use axum::{
    Router,
    extract::{Multipart, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::fs;
use tower_http::trace::TraceLayer;
// =======================================
// Configuration Structures
// =======================================

/// Server configuration including peer information
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// This server's unique ID
    pub server_id: u64,

    /// This server's priority (higher = more priority)
    pub priority: u32,

    /// Client middleware listener port
    pub client_port: u16, // 8000

    /// Server-to-server communication port
    pub peer_port: u16, // 8001

    /// Internal server port (for encryption processing)
    pub internal_server_port: u16, // 7000

    /// List of peer server middlewares (for election)
    pub peers: Vec<PeerInfo>,

    /// Election timeout in milliseconds (listen period)
    pub election_timeout_ms: u64, // 5000 (5 seconds)
}

/// Information about a peer server
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub server_id: u64,
    pub address: String, // e.g., "192.168.1.10:8001"
}

// =======================================
// Election Data Structures
// =======================================

/// Priority announcement message (broadcast only, no response)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PriorityAnnouncement {
    pub request_id: u64,
    pub server_id: u64,
    pub priority: u32,
}

/// Result of an election process
#[derive(Debug, Clone)]
pub struct ElectionResult {
    pub request_id: u64,
    pub is_leader: bool,
    pub highest_priority_seen: u32,
}

/// Tracks ongoing elections
pub struct ElectionTracker {
    /// Map: request_id -> election state
    active_elections: Arc<Mutex<HashMap<u64, ElectionState>>>,
}

/// State of a single election
struct ElectionState {
    request_id: u64,
    initiated_at: Instant,
    my_priority: u32,
    highest_priority_seen: u32, // Track highest priority announcement received
    should_process: bool,
}

impl ElectionTracker {
    pub fn new() -> Self {
        ElectionTracker {
            active_elections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start tracking a new election
    pub fn start_election(&self, request_id: u64, my_priority: u32) {
        let mut elections = self.active_elections.lock().unwrap();
        elections.insert(
            request_id,
            ElectionState {
                request_id,
                initiated_at: Instant::now(),
                my_priority,
                highest_priority_seen: my_priority,
                should_process: true, // Assume true until higher priority received
            },
        );
    }

    /// Record a priority announcement from a peer
    /// Returns true if we should immediately drop the request
    pub fn record_announcement(&self, request_id: u64, peer_priority: u32) -> bool {
        let mut elections = self.active_elections.lock().unwrap();
        if let Some(state) = elections.get_mut(&request_id) {
            // If peer has HIGHER priority, we should drop
            if peer_priority > state.my_priority {
                println!(
                    "[Election] [Req #{}] Received higher priority {} (mine: {})",
                    request_id, peer_priority, state.my_priority
                );
                state.highest_priority_seen = peer_priority;
                state.should_process = false;
                return true; // Drop immediately
            }
        }
        false // Continue
    }

    /// Check if we should process this request (after timeout)
    pub fn should_process(&self, request_id: u64) -> bool {
        let elections = self.active_elections.lock().unwrap();
        if let Some(state) = elections.get(&request_id) {
            state.should_process
        } else {
            false
        }
    }

    /// Mark election as completed
    pub fn complete_election(&self, request_id: u64) {
        let mut elections = self.active_elections.lock().unwrap();
        elections.remove(&request_id);
    }
}

// =======================================
// Legacy Structures (kept for compatibility)
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

/// Main server middleware struct with simplified election support
#[derive(Clone)]
pub struct ServerMiddleware {
    pub config: ServerConfig,
    pub election_tracker: Arc<ElectionTracker>,
}

impl ServerMiddleware {
    /// Create new server middleware with configuration
    pub fn new(config: ServerConfig) -> Self {
        ServerMiddleware {
            config,
            election_tracker: Arc::new(ElectionTracker::new()),
        }
    }

    /// Start both client and peer listeners
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create storage directory
        fs::create_dir_all("./server_storage").await?;

        println!("========================================");
        println!("Cloud P2P Server Middleware");
        println!("========================================");
        println!("[Server] ID: {}", self.config.server_id);
        println!("[Server] Priority: {}", self.config.priority);
        println!("[Server] Client port: {}", self.config.client_port);
        println!("[Server] Peer port: {}", self.config.peer_port);
        println!("[Server] Peers: {}", self.config.peers.len());
        println!(
            "[Server] Election timeout: {}ms",
            self.config.election_timeout_ms
        );
        println!("========================================\n");

        // Clone self for the peer listener
        let peer_self = self.clone();
        let peer_listener = tokio::spawn(async move {
            if let Err(e) = peer_self.start_peer_listener().await {
                eprintln!("[Server] Peer listener error: {}", e);
            }
        });

        // Start client listener in main task
        let client_listener = self.start_client_listener();

        // Wait for client listener (peer listener runs in background)
        tokio::select! {
            result = client_listener => result?,
            _ = peer_listener => {},
        }

        Ok(())
    }

    /// Start listener for peer-to-peer priority announcements (Port 8001)
    async fn start_peer_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", self.config.peer_port);

        let state = Arc::new(self.clone());

        let app = Router::new()
            .route("/announce", post(handle_priority_announcement))
            .with_state(state);

        println!("[Server] Peer listener started on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Start listener for client middleware requests (Port 8000)
    async fn start_client_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", self.config.client_port);

        let state = Arc::new(self.clone());

        let app = Router::new()
            .route("/", get(root_handler))
            .route("/health", get(health_handler))
            .route("/encrypt", post(encrypt_handler))
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        println!("[Server] Client listener started on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Start election process for a request
    /// Broadcasts priority to all peers and waits for higher priority announcements
    pub async fn start_election(&self, request_id: u64) -> ElectionResult {
        println!(
            "[Election] [Req #{}] Starting election (Server {}, Priority {})",
            request_id, self.config.server_id, self.config.priority
        );

        // Start tracking this election
        self.election_tracker
            .start_election(request_id, self.config.priority);

        // Broadcast priority to all peers (no response expected)
        self.broadcast_priority(request_id).await;

        println!(
            "[Election] [Req #{}] Listening for {}ms for higher priority announcements...",
            request_id, self.config.election_timeout_ms
        );

        // Wait for the election timeout period
        tokio::time::sleep(Duration::from_millis(self.config.election_timeout_ms)).await;

        // Check if we should process (no higher priority received)
        let should_process = self.election_tracker.should_process(request_id);

        let result = ElectionResult {
            request_id,
            is_leader: should_process,
            highest_priority_seen: self.config.priority,
        };

        if should_process {
            println!(
                "[Election] [Req #{}] ✓ I AM THE LEADER (Server {}, Priority {})",
                request_id, self.config.server_id, self.config.priority
            );
        } else {
            println!(
                "[Election] [Req #{}] ✗ Not leader (higher priority received)",
                request_id
            );
        }

        self.election_tracker.complete_election(request_id);

        result
    }

    /// Broadcast priority announcement to all peers (fire and forget, no response)
    async fn broadcast_priority(&self, request_id: u64) {
        let client = reqwest::Client::new();

        let announcement = PriorityAnnouncement {
            request_id,
            server_id: self.config.server_id,
            priority: self.config.priority,
        };

        for peer in &self.config.peers {
            let url = format!("http://{}/announce", peer.address);
            let announcement = announcement.clone();
            let client = client.clone();
            let peer_id = peer.server_id;

            tokio::spawn(async move {
                match client.post(&url).json(&announcement).send().await {
                    Ok(_) => {
                        println!(
                            "[Election] Broadcasted priority to peer {} (no response expected)",
                            peer_id
                        );
                    }
                    Err(e) => {
                        eprintln!("[Election] Failed to send to peer {}: {}", peer_id, e);
                    }
                }
            });
        }
    }
}

// =======================================
// HTTP Handlers - Peer Communication
// =======================================

/// Handle incoming priority announcements from peers
/// This is a one-way broadcast - no response is sent back
async fn handle_priority_announcement(
    State(middleware): State<Arc<ServerMiddleware>>,
    Json(announcement): Json<PriorityAnnouncement>,
) -> Json<serde_json::Value> {
    println!(
        "[Election] [Req #{}] Received priority announcement from Server {} (priority: {})",
        announcement.request_id, announcement.server_id, announcement.priority
    );

    // Record the announcement - if higher priority, drop our request
    let should_drop = middleware
        .election_tracker
        .record_announcement(announcement.request_id, announcement.priority);

    if should_drop {
        println!(
            "[Election] [Req #{}] ⚠️ Dropping request due to higher priority announcement",
            announcement.request_id
        );
    }

    // Simple acknowledgment (peers don't wait for this)
    Json(serde_json::json!({
        "status": "received"
    }))
}

// =======================================
// HTTP Handlers - Client Middleware API
// =======================================

/// Root endpoint
async fn root_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "Cloud P2P Server Middleware",
        "version": "2.0.0",
        "endpoints": {
            "health": "/health",
            "encrypt": "/encrypt (POST multipart/form-data)",
            "announce": "/announce (POST - peer priority announcements)"
        }
    }))
}

/// Health check endpoint
async fn health_handler() -> Json<serde_json::Value> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": timestamp
    }))
}

/// Encrypt image endpoint with simplified election algorithm
/// 1. Broadcast priority to all peers
/// 2. Listen for 5 seconds for higher priority
/// 3. If higher priority received -> drop request
/// 4. If no higher priority -> process request
async fn encrypt_handler(
    State(middleware): State<Arc<ServerMiddleware>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    println!("[Server Middleware] Received encrypt request");

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

    // Validate request
    if filename.is_empty() || file_data.is_empty() {
        return Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "ERROR",
            "message": "Missing filename or file data"
        })));
    }

    println!(
        "[Server Middleware] [Req #{}] Received encryption request: {} ({} bytes)",
        request_id,
        filename,
        file_data.len()
    );

    // ========================================
    // ELECTION PHASE
    // ========================================
    std::thread::sleep(std::time::Duration::from_millis(2000));

    println!(
        "[Server Middleware] [Req #{}] Starting election (Server ID: {}, Priority: {})",
        request_id, middleware.config.server_id, middleware.config.priority
    );

    // Start election: broadcast priority and wait for higher priority announcements
    let election_result = middleware.start_election(request_id).await;

    // If not elected as leader, ignore this request
    if !election_result.is_leader {
        println!(
            "[Server Middleware] [Req #{}] Not elected as leader - dropping request",
            request_id
        );

        return Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "ignored",
            "message": format!(
                "Not the elected leader for this request (Server {} received higher priority)",
                middleware.config.server_id
            )
        })));
    }

    // ========================================
    // PROCESSING PHASE (Leader Only)
    // ========================================

    println!(
        "[Server Middleware] [Req #{}] ✓ ELECTED AS LEADER - processing request",
        request_id
    );

    // Build EncryptionRequest for internal server
    let encryption_request = serde_json::json!({
        "request_id": request_id,
        "filename": filename,
        "file_data": file_data,
    });

    // Forward to internal server (TCP)
    let server_addr = format!("127.0.0.1:{}", middleware.config.internal_server_port);

    println!(
        "[Server Middleware] [Req #{}] Forwarding to internal server at {}",
        request_id, server_addr
    );

    let server_id = middleware.config.server_id;

    match tokio::task::spawn_blocking(move || {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpStream;

        // Connect to internal server
        let mut stream = match TcpStream::connect(&server_addr) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to connect to internal server: {}", e)),
        };

        // Serialize and send request
        let req_str = serde_json::to_string(&encryption_request).unwrap();
        if let Err(e) = stream.write_all(req_str.as_bytes()) {
            return Err(format!("Failed to send request: {}", e));
        }
        if let Err(e) = stream.write_all(b"\n") {
            return Err(format!("Failed to send newline: {}", e));
        }

        // Read response
        let mut reader = BufReader::new(stream);
        let mut response_line = String::new();
        if let Err(e) = reader.read_line(&mut response_line) {
            return Err(format!("Failed to read response: {}", e));
        }

        Ok(response_line)
    })
    .await
    {
        Ok(Ok(response_line)) => {
            // Parse EncryptionResponse from internal server
            match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                Ok(resp_json) => {
                    let status = resp_json["status"].as_str().unwrap_or("ERROR");
                    let message = resp_json["message"].as_str().unwrap_or("");
                    let output_filename = format!("encrypted_{}", filename);

                    // Extract encrypted data from response
                    let encrypted_data = resp_json["encrypted_data"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|b| b as u8))
                                .collect::<Vec<u8>>()
                        })
                        .unwrap_or_default();

                    if encrypted_data.is_empty() {
                        eprintln!(
                            "[Server Middleware] [Req #{}] Warning: No encrypted data in response",
                            request_id
                        );
                    }

                    // Encode as base64 for JSON transmission
                    let base64_data = base64_helper::encode(&encrypted_data);

                    println!(
                        "[Server Middleware] [Req #{}] ✓ Encryption complete - returning {} bytes",
                        request_id,
                        encrypted_data.len()
                    );

                    Ok(Json(serde_json::json!({
                        "request_id": request_id,
                        "status": status,
                        "message": message,
                        "output_filename": output_filename,
                        "file_data": base64_data,
                        "file_size": encrypted_data.len(),
                        "processed_by": server_id,
                    })))
                }
                Err(e) => {
                    eprintln!(
                        "[Server Middleware] [Req #{}] Failed to parse server response: {}",
                        request_id, e
                    );
                    Ok(Json(serde_json::json!({
                        "request_id": request_id,
                        "status": "ERROR",
                        "message": format!("Failed to parse server response: {}", e)
                    })))
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!(
                "[Server Middleware] [Req #{}] Server communication error: {}",
                request_id, e
            );
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": format!("Server communication error: {}", e)
            })))
        }
        Err(e) => {
            eprintln!(
                "[Server Middleware] [Req #{}] Task join error: {}",
                request_id, e
            );
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": format!("Internal error: {}", e)
            })))
        }
    }
}

// =======================================
// Helper Modules
// =======================================

/// Base64 encoding/decoding helper functions
mod base64_helper {
    use base64::{Engine as _, engine::general_purpose};

    pub fn encode(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    #[allow(dead_code)]
    pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(data)
    }
}
