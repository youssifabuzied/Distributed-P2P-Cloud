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
    let server_url = "http://127.0.0.1:8000";

    // Start middleware in background thread
    let middleware = ClientMiddleware::new(middleware_ip, middleware_port, server_url);
    let handle = thread::spawn(move || {
        if let Err(e) = middleware.start() {
            eprintln!("[main] middleware error: {}", e);
        }
    });

    // Give middleware a moment to bind
    thread::sleep(Duration::from_millis(150));

    // Start client UI (blocks until user exits)
    let middleware_addr = format!("{}:{}", middleware_ip, middleware_port);
    let client = Client::new(username, client_ip, client_port, &middleware_addr);
    client.start_ui();

    // When client exits, try to join middleware thread (may block until listener closes)
    let _ = handle.join();
}
