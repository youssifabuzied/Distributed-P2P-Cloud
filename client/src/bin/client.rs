// =======================================
// client.rs
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Responsibilities:
// 1. Maintain client metadata (username, peer list, etc.)
// 2. Send encryption/decryption requests to client middleware
// 3. Provide basic CLI / UI interface for testing
//

use std::io::{self, Write};
use std::net::{TcpStream};
use std::path::Path;
use std::fs::File;
use std::io::Read;
use serde::{Serialize, Deserialize};
use std::error::Error;

// ---------------------------------------
// Data Structures
// ---------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientMetadata {
    pub username: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    EncryptImage { image_path: String },
    DecryptImage { image_path: String },
}

// ---------------------------------------
// Client Definition
// ---------------------------------------

pub struct Client {
    pub metadata: ClientMetadata,
    pub middleware_addr: String, // e.g., "127.0.0.1:9000"
}

impl Client {
    pub fn new(username: &str, ip: &str, port: u16, middleware_addr: &str) -> Self {
        Client {
            metadata: ClientMetadata {
                username: username.to_string(),
                ip: ip.to_string(),
                port,
            },
            middleware_addr: middleware_addr.to_string(),
        }
    }

    /// Send request to client middleware
    pub fn send_request(&self, request: &ClientRequest) -> Result<(), Box<dyn Error>> {
        let mut stream = TcpStream::connect(&self.middleware_addr)?;
        let serialized = serde_json::to_string(request)?;
        stream.write_all(serialized.as_bytes())?;
        println!("[Client] Request sent to middleware: {:?}", request);
        Ok(())
    }

    /// Request encryption of an image
    pub fn request_encryption(&self, image_path: &str) -> Result<(), Box<dyn Error>> {
        if !Path::new(image_path).exists() {
            return Err("Image file not found".into());
        }
        let request = ClientRequest::EncryptImage {
            image_path: image_path.to_string(),
        };
        self.send_request(&request)
    }

    /// Simple CLI interface for testing
    pub fn start_ui(&self) {
        println!("Welcome, {}!", self.metadata.username);
        println!("Enter 'encrypt <image_path>' or 'decrypt <image_path>' or 'exit'.");

        loop {
            print!("> ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let tokens: Vec<&str> = input.trim().split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            match tokens[0] {
                "encrypt" if tokens.len() == 2 => {
                    if let Err(e) = self.request_encryption(tokens[1]) {
                        eprintln!("Error: {}", e);
                    }
                }
                "decrypt" if tokens.len() == 2 => {
                    let request = ClientRequest::DecryptImage {
                        image_path: tokens[1].to_string(),
                    };
                    if let Err(e) = self.send_request(&request) {
                        eprintln!("Error: {}", e);
                    }
                }
                "exit" => break,
                _ => println!("Invalid command."),
            }
        }
    }
}

// ---------------------------------------
// Entry point
// ---------------------------------------

fn main() {
    let client = Client::new("user1", "127.0.0.1", 8080, "127.0.0.1:9000");
    client.start_ui();
}
