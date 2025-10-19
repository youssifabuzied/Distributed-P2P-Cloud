mod client;
mod middleware;

use client::Client;
use middleware::ClientMiddleware;

use std::thread;
use std::time::Duration;

fn main() {
    // Configuration
    let username = "user1";
    let client_ip = "127.0.0.1";
    let client_port = 8080u16;
    let middleware_ip = "127.0.0.1";
    let middleware_port = 9000u16;

    // ✨ NEW: Define multiple server URLs
    let server_urls = vec![
        "http://127.0.0.1:8000".to_string(),    // Server 1
        "http://10.40.40.202:8000".to_string(), // Server 2 (if running)
    ];

    // Start middleware with multiple servers
    let middleware = ClientMiddleware::new(middleware_ip, middleware_port, server_urls);
    let handle = thread::spawn(move || {
        if let Err(e) = middleware.start() {
            eprintln!("[main] middleware error: {}", e);
        }
    });

    // Give middleware a moment to bind
    thread::sleep(Duration::from_millis(150));

    // Start client UI
    let middleware_addr = format!("{}:{}", middleware_ip, middleware_port);
    let client = Client::new(username, client_ip, client_port, &middleware_addr);
    client.start_ui();

    let _ = handle.join();
}
