// =======================================
// middleware.rs - Fixed Version
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Responsibilities:
// - Listen for HTTP requests from client middlewares (Port 8000)
// - Process image encryption requests with election algorithm
// - Communicate with peer servers for election (Port 8001)

use axum::{
    Router,
    extract::{Multipart, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

    /// Election timeout in milliseconds
    pub election_timeout_ms: u64, // e.g., 2000

    /// Random wait before election (min, max) in milliseconds
    pub election_wait_range: (u64, u64), // e.g., (100, 500)
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

/// Election-related message types for peer-to-peer communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ElectionMessage {
    /// Election initiation message
    Election {
        request_id: u64,      // Client request being processed
        initiator_id: u64,    // Server that started election
        sender_id: u64,       // Current sender's ID
        sender_priority: u32, // Current sender's priority
    },

    /// Response to election (only from higher priority servers)
    ElectionResponse {
        request_id: u64,
        responder_id: u64,
        responder_priority: u32,
    },

    /// Leader announcement (optional, for confirmation)
    Leader { request_id: u64, leader_id: u64 },
}

/// Result of an election process
#[derive(Debug, Clone)]
pub struct ElectionResult {
    pub request_id: u64,
    pub is_leader: bool,
    pub leader_id: u64,
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
    received_responses: Vec<(u64, u32)>, // (server_id, priority)
    has_sent_election: bool,
}

impl ElectionTracker {
    pub fn new() -> Self {
        ElectionTracker {
            active_elections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start tracking a new election
    pub fn start_election(&self, request_id: u64) {
        let mut elections = self.active_elections.lock().unwrap();
        elections.insert(
            request_id,
            ElectionState {
                request_id,
                initiated_at: Instant::now(),
                received_responses: Vec::new(),
                has_sent_election: false,
            },
        );
    }

    /// Record a response to an election
    pub fn add_response(&self, request_id: u64, server_id: u64, priority: u32) {
        let mut elections = self.active_elections.lock().unwrap();
        if let Some(state) = elections.get_mut(&request_id) {
            state.received_responses.push((server_id, priority));
        }
    }

    /// Check if election timed out
    pub fn is_timeout(&self, request_id: u64, timeout_ms: u64) -> bool {
        let elections = self.active_elections.lock().unwrap();
        if let Some(state) = elections.get(&request_id) {
            state.initiated_at.elapsed().as_millis() > timeout_ms as u128
        } else {
            false
        }
    }

    /// Get election result (if leader)
    pub fn has_responses(&self, request_id: u64) -> bool {
        let elections = self.active_elections.lock().unwrap();
        if let Some(state) = elections.get(&request_id) {
            !state.received_responses.is_empty()
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

/// Main server middleware struct with election support
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
        println!("[Server] Peers: {} connected", self.config.peers.len());
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

    /// Start listener for peer-to-peer election messages (Port 8001)
    async fn start_peer_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", self.config.peer_port);

        let state = Arc::new(self.clone());

        let app = Router::new()
            .route("/election", post(handle_election_message))
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
    pub async fn start_election(&self, request_id: u64) -> ElectionResult {
        // Random wait before starting election
        let wait_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(self.config.election_wait_range.0..=self.config.election_wait_range.1)
        };

        println!(
            "[Election] [Req #{}] Waiting {}ms before starting election",
            request_id, wait_ms
        );

        tokio::time::sleep(Duration::from_millis(wait_ms)).await;

        // Start tracking this election
        self.election_tracker.start_election(request_id);

        println!(
            "[Election] [Req #{}] Starting election (priority {})",
            request_id, self.config.priority
        );

        // Send election message to all peers
        self.broadcast_election(request_id).await;

        // Wait for responses or timeout
        tokio::time::sleep(Duration::from_millis(self.config.election_timeout_ms)).await;

        // Check if we're the leader
        let is_leader = !self.election_tracker.has_responses(request_id);

        let result = ElectionResult {
            request_id,
            is_leader,
            leader_id: if is_leader {
                self.config.server_id
            } else {
                0 // Unknown (would need to track)
            },
        };

        if is_leader {
            println!(
                "[Election] [Req #{}] ✓ I AM THE LEADER (Server {})",
                request_id, self.config.server_id
            );
        } else {
            println!(
                "[Election] [Req #{}] ✗ Not leader (received higher priority responses)",
                request_id
            );
        }

        self.election_tracker.complete_election(request_id);

        result
    }

    /// Broadcast election message to all peers
    async fn broadcast_election(&self, request_id: u64) {
        let client = reqwest::Client::new();

        let msg = ElectionMessage::Election {
            request_id,
            initiator_id: self.config.server_id,
            sender_id: self.config.server_id,
            sender_priority: self.config.priority,
        };

        for peer in &self.config.peers {
            let url = format!("http://{}/election", peer.address);
            let msg = msg.clone();
            let client = client.clone();
            let peer_id = peer.server_id;

            tokio::spawn(async move {
                match client.post(&url).json(&msg).send().await {
                    Ok(resp) => {
                        println!("[Election] Sent to peer {}: {:?}", peer_id, resp.status());
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

/// Handle incoming election messages from peers
async fn handle_election_message(
    State(middleware): State<Arc<ServerMiddleware>>,
    Json(msg): Json<ElectionMessage>,
) -> Json<serde_json::Value> {
    match msg {
        ElectionMessage::Election {
            request_id,
            initiator_id,
            sender_id,
            sender_priority,
        } => {
            // Only respond if we have HIGHER priority
            if middleware.config.priority > sender_priority {
                println!(
                    "[Election] [Req #{}] Received election from Server {} (priority {}), responding with priority {}",
                    request_id, sender_id, sender_priority, middleware.config.priority
                );

                // Send response back to sender
                let _response = ElectionMessage::ElectionResponse {
                    request_id,
                    responder_id: middleware.config.server_id,
                    responder_priority: middleware.config.priority,
                };

                // Also start our own election (if not already started)
                let middleware_clone = middleware.clone();
                tokio::spawn(async move {
                    middleware_clone.start_election(request_id).await;
                });

                Json(serde_json::json!({
                    "status": "responded",
                    "priority": middleware.config.priority
                }))
            } else {
                println!(
                    "[Election] [Req #{}] Ignoring election from Server {} (lower/equal priority)",
                    request_id, sender_id
                );

                Json(serde_json::json!({
                    "status": "ignored"
                }))
            }
        }

        ElectionMessage::ElectionResponse {
            request_id,
            responder_id,
            responder_priority,
        } => {
            // Record this response
            middleware
                .election_tracker
                .add_response(request_id, responder_id, responder_priority);

            Json(serde_json::json!({
                "status": "received"
            }))
        }

        ElectionMessage::Leader {
            request_id,
            leader_id,
        } => {
            println!(
                "[Election] [Req #{}] Leader is Server {}",
                request_id, leader_id
            );
            Json(serde_json::json!({"status": "acknowledged"}))
        }
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
            "encrypt": "/encrypt (POST multipart/form-data)"
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

/// Encrypt image endpoint with election algorithm
/// This handler receives encryption requests from client middleware,
/// runs an election to determine if this server should process the request,
/// and only processes if elected as leader
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

    println!(
        "[Server Middleware] [Req #{}] Starting election (Server ID: {}, Priority: {})",
        request_id, middleware.config.server_id, middleware.config.priority
    );

    // Start election to determine if this server should process the request
    let election_result = middleware.start_election(request_id).await;

    // If not elected as leader, ignore this request
    if !election_result.is_leader {
        println!(
            "[Server Middleware] [Req #{}] Not elected as leader - ignoring request",
            request_id
        );

        return Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "ignored",
            "message": format!(
                "Not the elected leader for this request (Server {} lost election)",
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

    // Forward to internal server (TCP, port 7000)
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
