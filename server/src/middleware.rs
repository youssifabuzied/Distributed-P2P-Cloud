use crate::directory_service;

use axum::extract::DefaultBodyLimit;
use axum::{
    Router,
    extract::{Multipart, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::fs;
use tokio::task;
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

    /// Failure simulation port (for Port 8002)
    pub failure_port: u16,

    /// Failure check interval in seconds
    pub failure_check_interval_secs: u64,

    /// Recovery timeout in seconds
    pub recovery_timeout_secs: u64,

    pub enable_failure_simulation: bool,
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
// Failure Simulation Structures
// =======================================

/// Failure announcement message for Port 8002
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FailureAnnouncement {
    pub server_id: u64,
    pub failure_score: u32,
    pub timestamp: u64,
}

/// Tracks failure state of this server
#[derive(Debug, Clone)]
pub struct FailureState {
    pub is_failed: bool,
    pub failed_at: Option<Instant>,
}

/// Tracks failure elections
pub struct FailureElectionTracker {
    /// Current failure scores from all servers
    scores: Arc<Mutex<HashMap<u64, u32>>>,
    /// This server's failure state
    state: Arc<Mutex<FailureState>>,
}

impl FailureElectionTracker {
    pub fn new() -> Self {
        FailureElectionTracker {
            scores: Arc::new(Mutex::new(HashMap::new())),
            state: Arc::new(Mutex::new(FailureState {
                is_failed: false,
                failed_at: None,
            })),
        }
    }

    /// Record a failure score from a peer
    pub fn record_score(&self, server_id: u64, score: u32) {
        self.scores.lock().unwrap().insert(server_id, score);
    }

    /// Check if this server is currently failed
    pub fn is_failed(&self) -> bool {
        self.state.lock().unwrap().is_failed
    }

    /// Mark this server as failed
    pub fn mark_failed(&self) {
        let mut state = self.state.lock().unwrap();
        state.is_failed = true;
        state.failed_at = Some(Instant::now());
    }

    /// Mark this server as recovered
    pub fn mark_recovered(&self) {
        let mut state = self.state.lock().unwrap();
        state.is_failed = false;
        state.failed_at = None;
        // Clear old scores
        self.scores.lock().unwrap().clear();
    }

    /// Get the highest failure score among all servers
    pub fn get_highest_score(&self) -> (u64, u32) {
        let scores = self.scores.lock().unwrap();
        scores
            .iter()
            .max_by_key(|&(_, &score)| score)
            .map(|(&id, &score)| (id, score))
            .unwrap_or((0, 0))
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
    pub failure_tracker: Arc<FailureElectionTracker>,
}

impl ServerMiddleware {
    /// Create new server middleware with configuration
    pub fn new(config: ServerConfig) -> Self {
        ServerMiddleware {
            config,
            election_tracker: Arc::new(ElectionTracker::new()),
            failure_tracker: Arc::new(FailureElectionTracker::new()), // ADD THIS LINE
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
        println!("[Server] Failure port: {}", self.config.failure_port);
        println!(
            "[Server] Failure simulation: {}",
            if self.config.enable_failure_simulation {
                "ENABLED"
            } else {
                "DISABLED"
            }
        );
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

        // Start client listener
        let client_listener = self.start_client_listener();

        // Conditionally start failure simulation
        if self.config.enable_failure_simulation {
            println!("[Server] Starting failure simulation subsystem...\n");

            // Clone self for failure listener
            let failure_self = self.clone();
            let failure_listener = tokio::spawn(async move {
                if let Err(e) = failure_self.start_failure_listener().await {
                    eprintln!("[Server] Failure listener error: {}", e);
                }
            });

            // Start failure election loop
            let election_self = Arc::new(self.clone());
            let failure_election = tokio::spawn(async move {
                election_self.run_failure_election_loop().await;
            });

            // Wait for any task to complete (all run in background)
            tokio::select! {
                result = client_listener => result?,
                _ = peer_listener => {},
                _ = failure_listener => {},
                _ = failure_election => {},
            }
        } else {
            println!("[Server] Failure simulation disabled - running normal mode\n");

            // Only run client and peer listeners
            tokio::select! {
                result = client_listener => result?,
                _ = peer_listener => {},
            }
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
            .route("/register", post(register_handler))
            .route("/add_image", post(add_image_handler))
            .route("/heartbeat", post(heartbeat_handler))
            .route("/fetch_users", post(fetch_users_handler))
            .route("/fetch_images", post(fetch_images_handler))
            .route("/request_access", post(request_access_handler))
            .layer(DefaultBodyLimit::max(1024 * 1024 * 100))
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        println!("[Server] Client listener started on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
    pub async fn start_election(&self, request_id: u64) -> ElectionResult {
        // Calculate dynamic priority based on system resources
        let dynamic_priority = self.calculate_dynamic_priority();

        println!(
            "[Election] [Req #{}] Starting election (Server {}, Base Priority: {}, Dynamic Priority: {})",
            request_id, self.config.server_id, self.config.priority, dynamic_priority
        );

        // Start tracking this election with dynamic priority
        self.election_tracker
            .start_election(request_id, dynamic_priority);

        // Broadcast priority to all peers (no response expected)
        self.broadcast_priority_with_value(request_id, dynamic_priority)
            .await;

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
            highest_priority_seen: dynamic_priority,
        };

        if should_process {
            println!(
                "[Election] [Req #{}] ✓ I AM THE LEADER (Server {}, Priority {})",
                request_id, self.config.server_id, dynamic_priority
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

    /// Calculate dynamic priority based on system resources
    /// Priority = (Available Memory %) * 50 + (100 - CPU Load %) * 50
    /// Higher value = better performance = higher priority
    fn calculate_dynamic_priority(&self) -> u32 {
        let mut sys = System::new_all();
        sys.refresh_all();

        // Get available memory percentage (0-100)
        let total_memory = sys.total_memory() as f32;
        let available_memory = sys.available_memory() as f32;
        let memory_percent = if total_memory > 0.0 {
            (available_memory / total_memory) * 100.0
        } else {
            0.0
        };

        // Get CPU load (average across all CPUs)
        sys.refresh_cpu();
        std::thread::sleep(std::time::Duration::from_millis(200)); // Wait for CPU stats
        sys.refresh_cpu();

        let cpu_usage: f32 =
            sys.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;

        // CPU availability = 100 - usage
        let cpu_availability = 100.0 - cpu_usage.min(100.0);

        // Calculate weighted priority (80% memory, 20% CPU)
        let priority = (memory_percent * 0.8 + cpu_availability * 0.2) as u32;

        println!(
            "[System] Server {}: Memory: {:.1}% available, CPU: {:.1}% available, Priority: {}",
            self.config.server_id, memory_percent, cpu_availability, priority
        );

        priority
    }
    /// Start election process for a request
    /// Broadcasts priority to all peers and waits for higher priority announcements
    /// Broadcast priority announcement to all peers (fire and forget, no response)
    async fn broadcast_priority_with_value(&self, request_id: u64, priority: u32) {
        let client = reqwest::Client::new();

        let announcement = PriorityAnnouncement {
            request_id,
            server_id: self.config.server_id,
            priority,
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
                            "[Election] Broadcasted priority {} to peer {} (no response expected)",
                            announcement.priority, peer_id
                        );
                    }
                    Err(e) => {
                        eprintln!("[Election] Failed to send to peer {}: {}", peer_id, e);
                    }
                }
            });
        }
    }
    /// Calculate failure score (higher = more likely to fail)
    /// Formula: (CPU Load × 0.3) + (Memory Usage × 0.3) + (Random × 0.4)
    fn calculate_failure_score(&self) -> u32 {
        let mut sys = System::new_all();
        sys.refresh_all();

        // Get CPU usage
        sys.refresh_cpu();
        thread::sleep(Duration::from_millis(200));
        sys.refresh_cpu();
        let cpu_usage: f32 =
            sys.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;

        // Get memory usage percentage
        let total_memory = sys.total_memory() as f32;
        let used_memory = sys.used_memory() as f32;
        let memory_usage_percent = if total_memory > 0.0 {
            (used_memory / total_memory) * 100.0
        } else {
            0.0
        };

        // Add random factor for unpredictability
        let mut rng = rand::thread_rng();
        let random_factor: f32 = rng.gen_range(0.0..100.0);

        // Calculate weighted failure score
        let failure_score =
            (cpu_usage * 0.3) + (memory_usage_percent * 0.3) + (random_factor * 0.4);

        println!(
            "[Failure] Server {}: CPU: {:.1}%, Memory: {:.1}%, Random: {:.1}, Score: {:.0}",
            self.config.server_id, cpu_usage, memory_usage_percent, random_factor, failure_score
        );

        failure_score as u32
    }

    /// Start failure election listener (Port 8002)
    async fn start_failure_listener(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", self.config.failure_port);

        let state = Arc::new(self.clone());

        let app = Router::new()
            .route("/announce_failure", post(handle_failure_announcement))
            .with_state(state);

        println!("[Server] Failure listener started on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Run failure election loop in background
    async fn run_failure_election_loop(self: Arc<Self>) {
        loop {
            // Wait for the interval
            tokio::time::sleep(Duration::from_secs(self.config.failure_check_interval_secs)).await;

            // REMOVED: Skip if already failed
            // Now server participates in elections even when failed

            println!(
                "\n[Failure Election] Starting failure check (Server {})",
                self.config.server_id
            );

            // Calculate my failure score
            let my_score = self.calculate_failure_score();

            // Record my own score
            self.failure_tracker
                .record_score(self.config.server_id, my_score);

            // Broadcast to all peers
            self.broadcast_failure_score(my_score).await;

            // Wait for announcements
            println!("[Failure Election] Listening for 40 seconds...");
            tokio::time::sleep(Duration::from_secs(40)).await;

            // Check if I have the highest score
            let (winner_id, highest_score) = self.failure_tracker.get_highest_score();

            // Only initiate failure if not already failed
            if winner_id == self.config.server_id && !self.failure_tracker.is_failed() {
                println!(
                    "\n[Failure Election] ⚠️  I AM FAILING (Server {}, Score: {})",
                    self.config.server_id, my_score
                );
                println!("[Failure Election] Initiating controlled failure...\n");

                // Mark as failed
                self.failure_tracker.mark_failed();

                // Spawn recovery task
                let recovery_self = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(
                        recovery_self.config.recovery_timeout_secs,
                    ))
                    .await;

                    println!(
                        "\n[Recovery] ✓ Server {} recovering after {} seconds",
                        recovery_self.config.server_id, recovery_self.config.recovery_timeout_secs
                    );
                    recovery_self.failure_tracker.mark_recovered();
                    println!(
                        "[Recovery] Server {} back online\n",
                        recovery_self.config.server_id
                    );
                });
            } else if winner_id == self.config.server_id && self.failure_tracker.is_failed() {
                println!(
                    "[Failure Election] I would fail again (Score: {}), but already in failed state",
                    my_score
                );
            } else {
                println!(
                    "[Failure Election] Server {} will fail (Score: {}), I'm safe (Score: {})",
                    winner_id, highest_score, my_score
                );
            }
        }
    }

    /// Broadcast failure score to all peers
    async fn broadcast_failure_score(&self, score: u32) {
        let client = reqwest::Client::new();

        let announcement = FailureAnnouncement {
            server_id: self.config.server_id,
            failure_score: score,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        for peer in &self.config.peers {
            let url = format!(
                "http://{}/announce_failure",
                peer.address.replace(":8001", ":8002")
            );
            let announcement = announcement.clone();
            let client = client.clone();
            let peer_id = peer.server_id;

            tokio::spawn(async move {
                match client.post(&url).json(&announcement).send().await {
                    Ok(_) => {
                        println!(
                            "[Failure Election] Sent score {} to peer {}",
                            announcement.failure_score, peer_id
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[Failure Election] Failed to send to peer {}: {}",
                            peer_id, e
                        );
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
pub async fn encrypt_handler(
    State(middleware): State<Arc<ServerMiddleware>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    println!("[Server Middleware] Received encrypt request");
    let mut request_id = 0u64;
    let mut filename = String::new();
    let mut file_data: Vec<u8> = Vec::new();
    let mut views: HashMap<String, u64> = HashMap::new();
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
            "views" => {
                //VIEWS NEED TO CHANGE
                let data = field.text().await.unwrap();
                views = serde_json::from_str(&data).unwrap_or_default();
            }
            "file" => {
                file_data = field.bytes().await.unwrap().to_vec();
            }
            _ => {}
        }
    }

    if middleware.failure_tracker.is_failed() {
        println!(
            "[Failure] [Req #{}] Server {} FAILED - hanging connection",
            request_id, middleware.config.server_id
        );

        // Hang indefinitely
        std::future::pending::<()>().await;

        // Never reached
        unreachable!();
    }

    // ========================================
    // 1. Parse multipart form data
    // ========================================
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
            "views" => {
                //VIEWS NEED TO CHANGE
                let data = field.text().await.unwrap();
                views = serde_json::from_str(&data).unwrap_or_default();
            }
            "file" => {
                file_data = field.bytes().await.unwrap().to_vec();
            }
            _ => {}
        }
    }

    // ========================================
    // 2. Check if server is failed before processing
    // ========================================
    if middleware.failure_tracker.is_failed() {
        println!(
            "[Failure] [Req #{}] Server {} FAILED - hanging connection",
            request_id, middleware.config.server_id
        );

        // Hang indefinitely
        std::future::pending::<()>().await;

        // Never reached
        unreachable!();
    }

    // ========================================
    // 3. Validate input
    // ========================================
    if filename.is_empty() || file_data.is_empty() {
        return Ok(Json(json!({
            "request_id": request_id,
            "status": "ERROR",
            "message": "Missing filename or file data"
        })));
    }

    println!(
        "[Server Middleware] [Req #{}] Received encryption request: {} ({} bytes) ({:?} views)",
        request_id,
        filename,
        file_data.len(),
        views //VIEWS NEED TO CHANGE
    );

    // ========================================
    // 4. Election Phase
    // ========================================
    std::thread::sleep(std::time::Duration::from_millis(2000));

    if middleware.failure_tracker.is_failed() {
        println!(
            "[Failure] [Req #{}] Server {} FAILED - hanging connection",
            request_id, middleware.config.server_id
        );

        // Hang indefinitely
        std::future::pending::<()>().await;

        // Never reached
        unreachable!();
    }

    println!(
        "[Server Middleware] [Req #{}] Starting election (Server ID: {}, Priority: {})",
        request_id, middleware.config.server_id, middleware.config.priority
    );

    let election_result = middleware.start_election(request_id).await;

    if middleware.failure_tracker.is_failed() {
        println!(
            "[Failure] [Req #{}] Server {} FAILED - hanging connection",
            request_id, middleware.config.server_id
        );

        // Hang indefinitely
        std::future::pending::<()>().await;

        // Never reached
        unreachable!();
    }

    if !election_result.is_leader {
        println!(
            "[Server Middleware] [Req #{}] Not elected as leader - dropping request",
            request_id
        );
        return Ok(Json(json!({
            "request_id": request_id,
            "status": "ignored",
            "message": format!(
                "Not the elected leader for this request (Server {} received higher priority)",
                middleware.config.server_id
            )
        })));
    }

    // ========================================
    // 5. Processing Phase (Leader Only)
    // ========================================
    println!(
        "[Server Middleware] [Req #{}] ✓ ELECTED AS LEADER - processing request",
        request_id
    );

    // ✅ Added failure check before forwarding
    if middleware.failure_tracker.is_failed() {
        println!(
            "[Failure] [Req #{}] Server {} FAILED - hanging connection",
            request_id, middleware.config.server_id
        );

        // Hang indefinitely
        std::future::pending::<()>().await;

        // Never reached
        unreachable!();
    }

    let encryption_request = json!({
        "request_id": request_id,
        "filename": filename,
        "views": views, //VIEWS NEED TO CHANGE
        "file_data": file_data,
    });

    let server_addr = format!("127.0.0.1:{}", middleware.config.internal_server_port);
    let server_id = middleware.config.server_id;
    let failure_tracker = middleware.failure_tracker.clone(); // ✅ Clone tracker for use in blocking task

    println!(
        "[Server Middleware] [Req #{}] Forwarding to internal server at {}",
        request_id, server_addr
    );

    // ========================================
    // 6. Forward to Internal Server (with extra failure checks)
    // ========================================
    match task::spawn_blocking(move || {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpStream;

        // ✅ Check before connecting
        if failure_tracker.is_failed() {
            println!(
                "[Failure] [Req #{}] Server {} FAILED - hanging connection",
                request_id, middleware.config.server_id
            );

            // Hang indefinitely
            loop {
                std::thread::park();
            }
            // Never reached
            unreachable!();
        }

        let mut stream = match TcpStream::connect(&server_addr) {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to connect to internal server: {}", e)),
        };

        // ✅ Check before sending
        if failure_tracker.is_failed() {
            println!(
                "[Failure] [Req #{}] Server {} FAILED - hanging connection",
                request_id, middleware.config.server_id
            );

            // Hang indefinitely
            loop {
                std::thread::park();
            }
            // Never reached
            unreachable!();
        }

        // Send JSON request
        let req_str = serde_json::to_string(&encryption_request).unwrap();
        if let Err(e) = stream.write_all(req_str.as_bytes()) {
            return Err(format!("Failed to send request: {}", e));
        }
        if let Err(e) = stream.write_all(b"\n") {
            return Err(format!("Failed to send newline: {}", e));
        }

        // ✅ Check again before reading response
        if failure_tracker.is_failed() {
            println!(
                "[Failure] [Req #{}] Server {} FAILED - hanging connection",
                request_id, middleware.config.server_id
            );

            // Hang indefinitely
            loop {
                std::thread::park();
            }
            // Never reached
            unreachable!();
        }

        // Read response from internal server
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
            match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                Ok(resp_json) => {
                    let status = resp_json["status"].as_str().unwrap_or("ERROR");
                    let message = resp_json["message"].as_str().unwrap_or("");
                    let output_stem = Path::new(&filename)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("output");
                    let output_filename = format!("encrypted_{}", output_stem);
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

                    let base64_data = base64_helper::encode(&encrypted_data);

                    println!(
                        "[Server Middleware] [Req #{}] ✓ Encryption complete - returning {} bytes",
                        request_id,
                        encrypted_data.len()
                    );

                    Ok(Json(json!({
                        "request_id": request_id,
                        "status": status,
                        "message": message,
                        "output_filename": output_filename,
                        "file_data": base64_data,
                        "file_size": encrypted_data.len(),
                        "views": views, //VIEWS NEED TO CHANGE
                        "processed_by": server_id,
                    })))
                }
                Err(e) => {
                    eprintln!(
                        "[Server Middleware] [Req #{}] Failed to parse server response: {}",
                        request_id, e
                    );
                    Ok(Json(json!({
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
            Ok(Json(json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": e
            })))
        }
        Err(e) => {
            eprintln!(
                "[Server Middleware] [Req #{}] Task join error: {}",
                request_id, e
            );
            Ok(Json(json!({
                "request_id": request_id,
                "status": "ERROR",
                "message": format!("Internal error: {}", e)
            })))
        }
    }
}
/// Handle incoming failure announcements from peers (Port 8002)
async fn handle_failure_announcement(
    State(middleware): State<Arc<ServerMiddleware>>,
    Json(announcement): Json<FailureAnnouncement>,
) -> Json<serde_json::Value> {
    println!(
        "[Failure Election] Received score {} from Server {}",
        announcement.failure_score, announcement.server_id
    );

    // Record the score
    middleware
        .failure_tracker
        .record_score(announcement.server_id, announcement.failure_score);

    Json(serde_json::json!({
        "status": "received"
    }))
}

// Register client
async fn register_handler(
    State(_middleware): State<Arc<ServerMiddleware>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request_id = payload["request_id"].as_u64().unwrap_or(0);
    let username = payload["username"].as_str().unwrap_or("");
    let ip = payload["ip"].as_str().unwrap_or("");

    println!(
        "[Server Middleware] [Req #{}] Received registration request: {} {}",
        request_id, username, ip
    );

    match directory_service::register_client(username, ip).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "success",
            "message": format!("Client {} registered successfully", username),
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "error",
            "message": format!("Registration failed: {}", e),
        }))),
    }
}

// Add image
async fn add_image_handler(
    State(_middleware): State<Arc<ServerMiddleware>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request_id = payload["request_id"].as_u64().unwrap_or(0);
    let username = payload["username"].as_str().unwrap_or("");
    let image_name = payload["image_name"].as_str().unwrap_or("");
    let image_bytes_b64 = payload["image_bytes"].as_str().unwrap_or("");

    println!(
        "[Server Middleware] [Req #{}] Received add image request: {} {} ({} bytes base64)",
        request_id,
        username,
        image_name,
        image_bytes_b64.len()
    );

    // Decode base64 image data
    let image_bytes = match general_purpose::STANDARD.decode(image_bytes_b64) {
        Ok(data) => data,
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "error",
                "message": format!("Failed to decode image data: {}", e),
            })));
        }
    };

    match directory_service::add_image(username, image_name, &image_bytes).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "success",
            "message": format!("Image {} added successfully for user {}", image_name, username),
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "error",
            "message": format!("Failed to add image: {}", e),
        }))),
    }
}

async fn heartbeat_handler(
    State(_middleware): State<Arc<ServerMiddleware>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request_id = payload["request_id"].as_u64().unwrap_or(0);
    let username = payload["username"].as_str().unwrap_or("");

    match directory_service::update_client_timestamp(username).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "success",
            "message": "Heartbeat received",
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "error",
            "message": format!("Heartbeat failed: {}", e),
        }))),
    }
}

async fn fetch_users_handler(
    State(_middleware): State<Arc<ServerMiddleware>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request_id = payload["request_id"].as_u64().unwrap_or(0);

    match directory_service::fetch_active_users().await {
        Ok(users) => {
            // Format users as readable string
            let user_list = if users.is_empty() {
                "No active users found".to_string()
            } else {
                users
                    .iter()
                    .map(|(username, ip)| format!("  {} - {}", username, ip))
                    .collect::<Vec<_>>()
                    .join("\n")
            };

            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "success",
                "message": user_list,
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "error",
            "message": format!("Failed to fetch users: {}", e),
        }))),
    }
}

// In server/src/middleware.rs - fetch_images_handler

async fn fetch_images_handler(
    State(_middleware): State<Arc<ServerMiddleware>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request_id = payload["request_id"].as_u64().unwrap_or(0);
    let target_username = payload["target_username"].as_str().unwrap_or("");

    println!("[Server] Fetching images for user: {}", target_username);

    match directory_service::fetch_user_images(target_username).await {
        Ok((is_online, images)) => {
            println!(
                "[Server] Got response - is_online: {}, images count: {}",
                is_online,
                images.len()
            );

            if !is_online {
                println!("[Server] User is not online");
                return Ok(Json(serde_json::json!({
                    "request_id": request_id,
                    "status": "error",
                    "message": format!("User '{}' is not online", target_username),
                })));
            }

            // images: Vec<(String, String)> where String is base64 encoded bytes
            let images_json: Vec<_> = images
                .iter()
                .map(|(name, bytes_b64)| {
                    serde_json::json!({
                        "image_name": name,
                        "image_bytes": bytes_b64
                    })
                })
                .collect();

            println!(
                "[Server] Sending response with {} images",
                images_json.len()
            );

            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "success",
                "images": images_json
            })))
        }

        Err(e) => {
            println!("[Server] Error fetching images: {}", e);
            Ok(Json(serde_json::json!({
                "request_id": request_id,
                "status": "error",
                "message": format!("Failed to fetch images: {}", e),
            })))
        }
    }
}

async fn request_access_handler(
    State(_middleware): State<Arc<ServerMiddleware>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let request_id = payload["request_id"].as_u64().unwrap_or(0);
    let owner = payload["owner"].as_str().unwrap_or("");
    let viewer = payload["viewer"].as_str().unwrap_or("");
    let image_name = payload["image_name"].as_str().unwrap_or("");
    let prop_views = payload["prop_views"].as_u64().unwrap_or(0);

    println!(
        "[Server Middleware] [Req #{}] Access request: {} -> {}'s '{}' ({} views)",
        request_id, viewer, owner, image_name, prop_views
    );

    match directory_service::request_image_access(owner, viewer, image_name, prop_views).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "success",
            "message": format!("Access request created for {} views of {}", prop_views, image_name),
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "request_id": request_id,
            "status": "error",
            "message": format!("Failed to create access request: {}", e),
        }))),
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
