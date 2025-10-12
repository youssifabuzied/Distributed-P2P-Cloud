// =======================================
// client_middleware.rs (Dummy Version)
// =======================================
//
// Responsibilities:
// - Receive requests from client.rs
// - Log request type
// - Return a dummy "OK" response
//

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::thread;

// ---------------------------------------
// Shared Structures
// ---------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    EncryptImage { image_path: String },
    DecryptImage { image_path: String },
}

// ---------------------------------------
// Client Middleware
// ---------------------------------------

pub struct ClientMiddleware {
    pub ip: String,
    pub port: u16,
}

impl ClientMiddleware {
    pub fn new(ip: &str, port: u16) -> Self {
        ClientMiddleware {
            ip: ip.to_string(),
            port,
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("{}:{}", self.ip, self.port);
        let listener = TcpListener::bind(&addr)?;
        println!("[ClientMiddleware] Listening on {}", addr);

        for stream in listener.incoming() {
            let stream = stream?;
            thread::spawn(move || {
                if let Err(e) = Self::handle_client_request(stream) {
                    eprintln!("[ClientMiddleware] Error: {}", e);
                }
            });
        }

        Ok(())
    }

    fn handle_client_request(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer)?;

        if buffer.is_empty() {
            return Ok(());
        }

        let request_str = String::from_utf8_lossy(&buffer);
        let request: Result<ClientRequest, _> = serde_json::from_str(&request_str);

        match request {
            Ok(req) => println!("[ClientMiddleware] Received request: {:?}", req),
            Err(_) => println!("[ClientMiddleware] Received unknown/invalid request"),
        }

        // Dummy OK response
        let response = serde_json::json!({ "status": "OK" }).to_string();
        stream.write_all(response.as_bytes())?;
        println!("[ClientMiddleware] Sent OK response.");

        Ok(())
    }
}

// ---------------------------------------
// Entry Point
// ---------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let middleware = ClientMiddleware::new("127.0.0.1", 9000);
    middleware.start()?;
    Ok(())
}
