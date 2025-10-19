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

    /// Internal server port
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
