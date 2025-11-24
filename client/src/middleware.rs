// =======================================
// middleware.rs - Updated to forward to Server Middleware
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Forwards encryption/decryption requests to server middleware via HTTP
//
//use aes_gcm::{Aes256Gcm, Key};
use crate::client::PendingRequest;
use base64::{Engine as _, engine::general_purpose};
use bincode;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use hex;
use png::text_metadata::ITXtChunk;
use png::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use stegano_core::api::unveil::prepare as extract_prepare;

// ---------------------------------------
// Shared Structures
// ---------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    //VIEWS NEED TO CHANGE
    EncryptImage {
        request_id: u64,
        image_path: String,
        views: HashMap<String, u64>, // Map of peer ID to allowed views
    },
    DecryptImage {
        request_id: u64,
        image_path: String,
        username: String,
    },
    RegisterWithDirectory {
        request_id: u64,
        username: String,
        ip: String,
    },
    AddImage {
        request_id: u64,
        username: String,
        image_name: String,
        image_bytes: Vec<u8>,
    },
    Heartbeat {
        request_id: u64,
        username: String,
    },
    FetchActiveUsers {
        request_id: u64,
    },
    FetchUserImages {
        request_id: u64,
        target_username: String,
    },
    RequestImageAccess {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
        prop_views: u64,
    },
    ViewPendingRequests {
        request_id: u64,
        username: String,
    },
    ApproveOrRejectAccess {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
        accep_views: i64,
    },
    GetAcceptedViews {
        request_id: u64,
        owner: String,
        viewer: String,
        image_name: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MiddlewareResponse {
    pub request_id: u64,
    pub status: String,
    pub message: Option<String>,
    pub output_path: Option<String>,
}

// Add this near the top with other structures
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ImageMetadata {
    owner: String,
    image_name: String,
    accepted_views: u64,
    views_count: u64,
}

impl MiddlewareResponse {
    pub fn success(request_id: u64, message: &str, output_path: Option<String>) -> Self {
        MiddlewareResponse {
            request_id,
            status: "OK".to_string(),
            message: Some(message.to_string()),
            output_path,
        }
    }

    pub fn error(request_id: u64, message: &str) -> Self {
        MiddlewareResponse {
            request_id,
            status: "ERROR".to_string(),
            message: Some(message.to_string()),
            output_path: None,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ServerResponse {
    pub request_id: u64,
    pub status: String,
    pub message: String,
    pub output_filename: Option<String>,
    pub file_data: Option<String>, // Base64 encoded
    pub file_size: Option<usize>,
}
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    //VIEWS NEED TO CHANGE + VIEWS NO LONGER IN PAYLOAD!!!!
    message: String,
    // views: HashMap<String, u64>,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
                          // extra: Option<String>,
}

// ---------------------------------------
// Client Middleware
// ---------------------------------------

pub struct ClientMiddleware {
    pub ip: String,
    pub port: u16,
    pub server_urls: Vec<String>, // Server middleware HTTP URL
}

impl ClientMiddleware {
    pub fn new(ip: &str, port: u16, server_urls: Vec<String>) -> Self {
        ClientMiddleware {
            ip: ip.to_string(),
            port,
            server_urls,
        }
    }

    pub fn handle_post_approval(
        server_urls: &[String],
        request_id: u64,
        owner: &str,
        viewer: &str,
        image_name: &str,
        accep_views: u64,
    ) -> MiddlewareResponse {
        println!(
            "[ClientMiddleware] [Req #{}] Starting post-approval workflow: {} -> {}'s '{}'",
            request_id, viewer, owner, image_name
        );

        // Step 1: Read the image from local disk
        let image_path = format!("{}", image_name);
        let image_bytes = match std::fs::read(&image_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to read image from disk: {}",
                    request_id, e
                );
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to read image '{}': {}", image_name, e),
                );
            }
        };

        println!(
            "[ClientMiddleware] [Req #{}] ✓ Read image from disk ({} bytes)",
            request_id,
            image_bytes.len()
        );

        // Step 2: Prepare views HashMap for encryption (only viewer with approved views)
        let mut views: HashMap<String, u64> = HashMap::new();
        views.insert(viewer.to_string(), accep_views);

        println!(
            "[ClientMiddleware] [Req #{}] Sending image for encryption with {} views for {}",
            request_id, accep_views, viewer
        );

        // Step 3: Send for encryption using existing encrypt function
        let encrypted_bytes = match Self::send_encrypt_to_single_server(
            &server_urls[0],
            request_id,
            image_name,
            &image_bytes,
            views,
        ) {
            Ok(response) => {
                if response.status != "OK" {
                    eprintln!(
                        "[ClientMiddleware] [Req #{}] Encryption failed: {:?}",
                        request_id, response.message
                    );
                    return MiddlewareResponse::error(
                        request_id,
                        &format!(
                            "Encryption failed: {}",
                            response.message.unwrap_or_default()
                        ),
                    );
                }

                // Extract encrypted data from response
                if let Some(file_data_b64) = response.output_path {
                    // output_path actually contains base64 data in our response
                    match general_purpose::STANDARD.decode(&file_data_b64) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            eprintln!(
                                "[ClientMiddleware] [Req #{}] Failed to decode encrypted data: {}",
                                request_id, e
                            );
                            return MiddlewareResponse::error(
                                request_id,
                                &format!("Failed to decode encrypted data: {}", e),
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "[ClientMiddleware] [Req #{}] No encrypted data in response",
                        request_id
                    );
                    return MiddlewareResponse::error(request_id, "No encrypted data in response");
                }
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Encryption request failed: {}",
                    request_id, e
                );
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Encryption request failed: {}", e),
                );
            }
        };

        println!(
            "[ClientMiddleware] [Req #{}] ✓ Encryption complete ({} bytes)",
            request_id,
            encrypted_bytes.len()
        );

        // Step 4: Fetch active users to get viewer's IP
        let viewer_ip = match Self::fetch_viewer_ip_from_server(server_urls, request_id, viewer) {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to fetch viewer IP: {}",
                    request_id, e
                );
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to fetch viewer IP: {}", e),
                );
            }
        };

        println!(
            "[ClientMiddleware] [Req #{}] ✓ Found viewer IP: {}",
            request_id, viewer_ip
        );

        // Step 5: Send encrypted image to viewer's client middleware
        match Self::send_encrypted_to_viewer(
            request_id,
            &viewer_ip,
            owner,
            image_name,
            &encrypted_bytes,
            accep_views,
        ) {
            Ok(_) => {
                println!(
                    "[ClientMiddleware] [Req #{}] ✓ Successfully delivered encrypted image to {}",
                    request_id, viewer
                );
                MiddlewareResponse::success(
                    request_id,
                    &format!("Image encrypted and delivered to {} successfully", viewer),
                    None,
                )
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to deliver to viewer: {}",
                    request_id, e
                );
                MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to deliver encrypted image: {}", e),
                )
            }
        }
    }

    // Helper: Fetch viewer's IP from server
    fn fetch_viewer_ip_from_server(
        server_urls: &[String],
        request_id: u64,
        viewer: &str,
    ) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let server_url = &server_urls[0];
        let url = format!("{}/fetch_users", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
        });

        println!(
            "[ClientMiddleware] [Req #{}] Fetching active users to find viewer IP...",
            request_id
        );

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<serde_json::Value>() {
                Ok(json_resp) => {
                    let message = json_resp["message"].as_str().unwrap_or("");

                    // Parse the message to extract user list
                    // Format: "  username - ip\n  username - ip\n..."
                    for line in message.lines() {
                        let parts: Vec<&str> = line.trim().split(" - ").collect();
                        if parts.len() == 2 {
                            let username = parts[0].trim();
                            let ip = parts[1].trim();

                            if username == viewer {
                                return Ok(ip.to_string());
                            }
                        }
                    }

                    Err(format!("Viewer '{}' not found in active users", viewer))
                }
                Err(e) => Err(format!("Failed to parse response: {}", e)),
            },
            Err(e) => Err(format!("Failed to contact server: {}", e)),
        }
    }

    // Helper: Send encrypted image to viewer's middleware via TCP
    fn send_encrypted_to_viewer(
        request_id: u64,
        viewer_ip: &str,
        owner: &str,
        image_name: &str,
        encrypted_data: &[u8],
        accepted_views: u64,
    ) -> Result<(), String> {
        use std::io::Write;
        use std::net::TcpStream;

        // Connect to viewer's client middleware (port 9000)
        let viewer_addr = format!("{}:9000", viewer_ip);

        println!(
            "[ClientMiddleware] [Req #{}] Connecting to viewer middleware at {}...",
            request_id, viewer_addr
        );

        let mut stream = TcpStream::connect(&viewer_addr)
            .map_err(|e| format!("Failed to connect to viewer middleware: {}", e))?;

        // Create a delivery request message
        let delivery_request = serde_json::json!({
            "type": "ReceiveEncryptedImage",
            "request_id": request_id,
            "owner": owner,
            "image_name": image_name,
            "encrypted_data": general_purpose::STANDARD.encode(encrypted_data),
            "accepted_views": accepted_views,
        });

        let request_json = serde_json::to_string(&delivery_request)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        // Send the request
        stream
            .write_all(request_json.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;
        stream
            .write_all(b"\n")
            .map_err(|e| format!("Failed to send newline: {}", e))?;
        stream
            .flush()
            .map_err(|e| format!("Failed to flush stream: {}", e))?;

        println!(
            "[ClientMiddleware] [Req #{}] ✓ Sent encrypted image to viewer",
            request_id
        );

        Ok(())
    }

    // Update the send_approve_access_to_server to trigger post-approval workflow
    fn send_approve_access_to_server(
        server_urls: &[String],
        request_id: u64,
        owner: &str,
        viewer: &str,
        image_name: &str,
        accep_views: i64,
    ) -> MiddlewareResponse {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let server_url = &server_urls[0];
        let url = format!("{}/approve_access", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "owner": owner,
            "viewer": viewer,
            "image_name": image_name,
            "accep_views": accep_views,
        });

        let action = if accep_views == -1 {
            "Rejecting"
        } else {
            "Approving"
        };

        println!(
            "[ClientMiddleware] [Req #{}] {} access request: {} -> {}'s '{}' ({} views)",
            request_id, action, viewer, owner, image_name, accep_views
        );

        match client.post(&url).json(&payload).send() {
            Ok(response) => {
                println!(
                    "[ClientMiddleware] [Req #{}] Received response from server",
                    request_id
                );

                match response.json::<ServerResponse>() {
                    Ok(server_resp) => {
                        if server_resp.status == "success" {
                            println!(
                                "[ClientMiddleware] [Req #{}] ✓ {}",
                                request_id, server_resp.message
                            );

                            // If approval (not rejection), start post-approval workflow
                            if accep_views > 0 {
                                println!(
                                    "[ClientMiddleware] [Req #{}] Starting encryption and delivery workflow...",
                                    request_id
                                );

                                // Clone server_urls for the workflow
                                let server_urls_vec = server_urls.to_vec();

                                // Execute post-approval workflow
                                return ClientMiddleware::handle_post_approval(
                                    &server_urls_vec,
                                    request_id,
                                    owner,
                                    viewer,
                                    image_name,
                                    accep_views as u64,
                                );
                            }

                            MiddlewareResponse::success(request_id, &server_resp.message, None)
                        } else {
                            eprintln!(
                                "[ClientMiddleware] [Req #{}] Error: {}",
                                request_id, server_resp.message
                            );
                            MiddlewareResponse::error(request_id, &server_resp.message)
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[ClientMiddleware] [Req #{}] Failed to parse response: {}",
                            request_id, e
                        );
                        MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to parse response: {}", e),
                        )
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to contact server: {}",
                    request_id, e
                );
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }

    fn send_get_accepted_views_to_server(
        server_urls: &[String],
        request_id: u64,
        owner: &str,
        viewer: &str,
        image_name: &str,
    ) -> MiddlewareResponse {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let server_url = &server_urls[0];
        let url = format!("{}/get_accepted_views", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "owner": owner,
            "viewer": viewer,
            "image_name": image_name,
        });

        println!(
            "[ClientMiddleware] [Req #{}] Getting accepted views: {} -> {}'s '{}'",
            request_id, viewer, owner, image_name
        );

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<ServerResponse>() {
                Ok(server_resp) => {
                    if server_resp.status == "success" {
                        // Extract accep_views from response (it's in the message or we can parse it)
                        println!(
                            "[ClientMiddleware] [Req #{}] ✓ {}",
                            request_id, server_resp.message
                        );
                        MiddlewareResponse::success(request_id, &server_resp.message, None)
                    } else {
                        eprintln!(
                            "[ClientMiddleware] [Req #{}] Error: {}",
                            request_id, server_resp.message
                        );
                        MiddlewareResponse::error(request_id, &server_resp.message)
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[ClientMiddleware] [Req #{}] Failed to parse response: {}",
                        request_id, e
                    );
                    MiddlewareResponse::error(
                        request_id,
                        &format!("Failed to parse response: {}", e),
                    )
                }
            },
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to contact server: {}",
                    request_id, e
                );
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }

    fn send_view_pending_requests_to_server(
        server_urls: &[String],
        request_id: u64,
        username: &str,
    ) -> Result<Vec<PendingRequest>, String> {
        // ← Changed return type
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let server_url = &server_urls[0];
        let url = format!("{}/view_pending_requests", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "username": username,
        });

        println!(
            "[ClientMiddleware] [Req #{}] Fetching pending requests for: {}",
            request_id, username
        );

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<serde_json::Value>() {
                Ok(json_resp) => {
                    let status = json_resp["status"].as_str().unwrap_or("error");

                    if status == "success" {
                        let message = json_resp["message"].as_str().unwrap_or("No requests");

                        println!("\n========================================");
                        println!("{}", message);
                        println!("========================================\n");

                        // ✅ NEW: Parse and return the requests
                        let mut requests = Vec::new();
                        if let Some(requests_array) = json_resp["requests"].as_array() {
                            for req in requests_array {
                                let viewer = req["viewer"].as_str().unwrap_or("").to_string();
                                let image_name =
                                    req["image_name"].as_str().unwrap_or("").to_string();
                                let prop_views = req["prop_views"].as_u64().unwrap_or(0);

                                requests.push(PendingRequest {
                                    viewer,
                                    image_name,
                                    prop_views,
                                });
                            }
                        }

                        Ok(requests) // ✅ Return the data
                    } else {
                        let message = json_resp["message"].as_str().unwrap_or("Unknown error");
                        Err(message.to_string())
                    }
                }
                Err(e) => Err(format!("Failed to parse response: {}", e)),
            },
            Err(e) => Err(format!("Failed to contact server: {}", e)),
        }
    }

    fn send_request_access_to_server(
        server_urls: &[String],
        request_id: u64,
        owner: &str,
        viewer: &str,
        image_name: &str,
        prop_views: u64,
    ) -> MiddlewareResponse {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let server_url = &server_urls[0];
        let url = format!("{}/request_access", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "owner": owner,
            "viewer": viewer,
            "image_name": image_name,
            "prop_views": prop_views,
        });

        println!(
            "[ClientMiddleware] [Req #{}] Forwarding access request to server: {} -> {}'s '{}' ({} views)",
            request_id, viewer, owner, image_name, prop_views
        );

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<ServerResponse>() {
                Ok(server_resp) => {
                    if server_resp.status == "success" {
                        MiddlewareResponse::success(request_id, &server_resp.message, None)
                    } else {
                        MiddlewareResponse::error(request_id, &server_resp.message)
                    }
                }
                Err(e) => MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to parse response: {}", e),
                ),
            },
            Err(e) => {
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }

    fn send_fetch_images_to_server(
        server_urls: &[String],
        request_id: u64,
        target_username: &str,
    ) -> MiddlewareResponse {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        // Try first available server
        let server_url = &server_urls[0];
        let url = format!("{}/fetch_images", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "target_username": target_username,
        });

        match client.post(&url).json(&payload).send() {
            Ok(response) => {
                println!("Got response from server!");

                match response.json::<serde_json::Value>() {
                    Ok(json_resp) => {
                        println!("Successfully parsed JSON response");
                        println!("Response: {:?}", json_resp);

                        let status = json_resp["status"].as_str().unwrap_or("error");
                        println!("Status: {}", status);

                        if status == "success" {
                            // Parse images array
                            if let Some(images_array) = json_resp["images"].as_array() {
                                println!("Found {} images", images_array.len());
                                println!("\n========================================");
                                println!("Images for user '{}':", target_username);
                                println!("========================================");

                                // Create client_storage directory if it doesn't exist
                                let storage_dir = "client_storage";
                                if let Err(e) = std::fs::create_dir_all(storage_dir) {
                                    eprintln!("Failed to create storage directory: {}", e);
                                }

                                for img in images_array {
                                    let image_name =
                                        img["image_name"].as_str().unwrap_or("unknown");
                                    let image_bytes_b64 = img["image_bytes"].as_str().unwrap_or("");

                                    println!("Processing image: {}", image_name);

                                    // Decode base64 to get actual bytes
                                    match general_purpose::STANDARD.decode(image_bytes_b64) {
                                        Ok(bytes) => {
                                            println!("  {} ({} bytes)", image_name, bytes.len());

                                            // Save to client_storage as PNG
                                            let output_path =
                                                format!("{}/{}", storage_dir, image_name);
                                            match std::fs::write(&output_path, &bytes) {
                                                Ok(_) => {
                                                    println!("  ✓ Saved to: {}", output_path);
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "  ✗ Failed to save {}: {}",
                                                        image_name, e
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            println!("  {} (decode error: {})", image_name, e);
                                        }
                                    }
                                }

                                println!("========================================\n");

                                MiddlewareResponse::success(
                                    request_id,
                                    "Images fetched and saved",
                                    None,
                                )
                            } else {
                                println!("No images array found in response");
                                MiddlewareResponse::error(request_id, "No images array in response")
                            }
                        } else {
                            let message = json_resp["message"].as_str().unwrap_or("Unknown error");
                            println!("Error: {}", message);
                            MiddlewareResponse::error(request_id, message)
                        }
                    }
                    Err(e) => {
                        println!("Failed to parse JSON: {}", e);
                        MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to parse response: {}", e),
                        )
                    }
                }
            }
            Err(e) => {
                println!("Failed to send request: {}", e);
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }

    fn send_fetch_users_to_server(server_urls: &[String], request_id: u64) -> MiddlewareResponse {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        // Try first available server
        let server_url = &server_urls[0];
        let url = format!("{}/fetch_users", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
        });

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<ServerResponse>() {
                Ok(server_resp) => {
                    if server_resp.status == "success" {
                        // Parse users from message (will be JSON string)
                        println!("\n========================================");
                        println!("Active Users:");
                        println!("========================================");
                        println!("{}", server_resp.message);
                        println!("========================================\n");

                        MiddlewareResponse::success(request_id, &server_resp.message, None)
                    } else {
                        MiddlewareResponse::error(request_id, &server_resp.message)
                    }
                }
                Err(e) => MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to parse response: {}", e),
                ),
            },
            Err(e) => {
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }

    fn send_heartbeat_to_server(
        server_urls: &[String],
        request_id: u64,
        username: &str,
    ) -> MiddlewareResponse {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Try first available server
        let server_url = &server_urls[0];
        let url = format!("{}/heartbeat", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "username": username,
        });

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<ServerResponse>() {
                Ok(server_resp) => {
                    if server_resp.status == "success" {
                        MiddlewareResponse::success(request_id, &server_resp.message, None)
                    } else {
                        MiddlewareResponse::error(request_id, &server_resp.message)
                    }
                }
                Err(_) => MiddlewareResponse::error(request_id, "Failed to parse response"),
            },
            Err(_) => {
                // Silent failure - will retry in 20 seconds
                MiddlewareResponse::error(request_id, "Heartbeat failed")
            }
        }
    }

    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr)?;

        println!("========================================");
        println!("Client Middleware ");
        println!("========================================");
        println!("[ClientMiddleware] Listening on {}]\n", addr);
        println!("[ClientMiddleware] Available servers:");
        for (i, url) in self.server_urls.iter().enumerate() {
            println!("  [{}] {}", i + 1, url);
        }

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    println!("[ClientMiddleware] New connection from: {}", peer_addr);

                    let server_urls = self.server_urls.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client_request(stream, &server_urls) {
                            eprintln!("[ClientMiddleware] Error handling request: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[ClientMiddleware] Connection error: {}", e);
                }
            }
        }

        Ok(())
    }

    fn handle_client_request(
        stream: TcpStream,
        server_urls: &[String],
    ) -> Result<(), Box<dyn Error>> {
        let mut reader = BufReader::new(&stream);
        let mut writer = stream.try_clone()?;

        // Read request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        if request_line.trim().is_empty() {
            return Ok(());
        }

        // Try to parse as JSON to determine request type
        let json_value: serde_json::Value = serde_json::from_str(request_line.trim())?;

        // Check if this is a delivery request (ReceiveEncryptedImage)
        // Check if this is a delivery request (ReceiveEncryptedImage)
        if let Some(req_type) = json_value["type"].as_str() {
            if req_type == "ReceiveEncryptedImage" {
                println!("[ClientMiddleware] Received encrypted image delivery");

                let request_id = json_value["request_id"].as_u64().unwrap_or(0);
                let owner = json_value["owner"].as_str().unwrap_or("unknown"); // ✅ Extract owner
                let image_name = json_value["image_name"].as_str().unwrap_or("");
                let encrypted_data_b64 = json_value["encrypted_data"].as_str().unwrap_or("");
                let accepted_views = json_value["accepted_views"].as_u64().unwrap_or(0); // ✅ Extract accepted_views

                // ✅ Handle the delivery with new parameters
                let response = Self::handle_receive_encrypted_image(
                    request_id,
                    owner,
                    image_name,
                    encrypted_data_b64,
                    accepted_views,
                );

                // Send acknowledgment back
                let response_json = serde_json::to_string(&response)?;
                writer.write_all(response_json.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;

                return Ok(());
            }
        }

        // Otherwise, parse as normal ClientRequest
        let response = match serde_json::from_str::<ClientRequest>(request_line.trim()) {
            Ok(request) => {
                let request_id = match &request {
                    ClientRequest::EncryptImage { request_id, .. } => *request_id,
                    ClientRequest::DecryptImage { request_id, .. } => *request_id,
                    ClientRequest::RegisterWithDirectory { request_id, .. } => *request_id,
                    ClientRequest::AddImage { request_id, .. } => *request_id,
                    ClientRequest::Heartbeat { request_id, .. } => *request_id,
                    ClientRequest::FetchActiveUsers { request_id } => *request_id,
                    ClientRequest::FetchUserImages { request_id, .. } => *request_id,
                    ClientRequest::RequestImageAccess { request_id, .. } => *request_id,
                    ClientRequest::ViewPendingRequests { request_id, .. } => *request_id,
                    ClientRequest::ApproveOrRejectAccess { request_id, .. } => *request_id,
                    ClientRequest::GetAcceptedViews { request_id, .. } => *request_id,
                };

                // Forward to appropriate handler
                Self::forward_to_servers(server_urls, request)
            }
            Err(e) => {
                eprintln!("[ClientMiddleware] Invalid request format: {}", e);
                MiddlewareResponse::error(0, "Invalid request format")
            }
        };

        // Send response back to client
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        println!(
            "[ClientMiddleware] Sent response to client for request #{}\n",
            response.request_id
        );

        Ok(())
    }

    // New handler for receiving encrypted images
    // New handler for receiving encrypted images
    fn handle_receive_encrypted_image(
        request_id: u64,
        owner: &str,
        image_name: &str,
        encrypted_data_b64: &str,
        accepted_views: u64,
    ) -> MiddlewareResponse {
        println!(
            "[ClientMiddleware] [Req #{}] Processing received encrypted image: {} from {}",
            request_id, image_name, owner
        );

        // Decode base64 data
        let encrypted_bytes = match general_purpose::STANDARD.decode(encrypted_data_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to decode encrypted data: {}",
                    request_id, e
                );
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to decode encrypted data: {}", e),
                );
            }
        };

        println!(
            "[ClientMiddleware] [Req #{}] Decoded {} bytes",
            request_id,
            encrypted_bytes.len()
        );

        // ✅ Create shared_images directory
        let storage_dir = "shared_images";
        if let Err(e) = std::fs::create_dir_all(storage_dir) {
            eprintln!(
                "[ClientMiddleware] [Req #{}] Failed to create shared_images directory: {}",
                request_id, e
            );
            return MiddlewareResponse::error(
                request_id,
                &format!("Failed to create shared_images directory: {}", e),
            );
        }

        // ✅ Save encrypted image file
        let image_path = format!("{}/{}", storage_dir, image_name);
        match std::fs::write(&image_path, &encrypted_bytes) {
            Ok(_) => {
                println!(
                    "[ClientMiddleware] [Req #{}] ✓ Saved encrypted image to: {}",
                    request_id, image_path
                );
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to save encrypted image: {}",
                    request_id, e
                );
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to save encrypted image: {}", e),
                );
            }
        }

        // ✅ Create metadata
        let metadata = ImageMetadata {
            owner: owner.to_string(),
            image_name: image_name.to_string(),
            accepted_views: accepted_views,
            views_count: 0, // Initialize to 0
        };

        // ✅ Save metadata file
        let metadata_filename = format!(
            "{}_metadata.json",
            std::path::Path::new(image_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("image")
        );
        let metadata_path = format!("{}/{}", storage_dir, metadata_filename);

        let metadata_json = match serde_json::to_string_pretty(&metadata) {
            Ok(json) => json,
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to serialize metadata: {}",
                    request_id, e
                );
                // Clean up image file
                let _ = std::fs::remove_file(&image_path);
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to serialize metadata: {}", e),
                );
            }
        };

        match std::fs::write(&metadata_path, metadata_json) {
            Ok(_) => {
                println!(
                    "[ClientMiddleware] [Req #{}] ✓ Saved metadata to: {}",
                    request_id, metadata_path
                );
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to save metadata: {}",
                    request_id, e
                );
                // Clean up image file
                let _ = std::fs::remove_file(&image_path);
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to save metadata: {}", e),
                );
            }
        }

        // ✅ Notify user
        println!("\n========================================");
        println!("📥 NEW SHARED IMAGE RECEIVED");
        println!("========================================");
        println!("Owner: {}", owner);
        println!("Image: {}", image_name);
        println!("Accepted Views: {}", accepted_views);
        println!("Current Views: 0");
        println!("Image saved to: {}", image_path);
        println!("Metadata saved to: {}", metadata_path);
        println!("========================================\n");

        MiddlewareResponse::success(
            request_id,
            &format!(
                "Encrypted image '{}' from '{}' received and saved with metadata (views: {}/{})",
                image_name, owner, 0, accepted_views
            ),
            Some(image_path),
        )
    }

    fn forward_to_servers(server_urls: &[String], request: ClientRequest) -> MiddlewareResponse {
        match request {
            //VIEWS NEED TO CHANGE
            ClientRequest::EncryptImage {
                request_id,
                image_path,
                views,
            } => {
                // Forward encryption to ALL servers and wait for first response
                //VIEWS NEED TO CHANGE
                Self::send_encrypt_to_multiple_servers(server_urls, request_id, &image_path, views)
            }
            ClientRequest::DecryptImage {
                request_id,
                image_path,
                username,
            } => {
                // Handle decryption locally (no server needed)
                Self::decrypt_image_locally(request_id, &image_path, &username)
            }
            ClientRequest::RegisterWithDirectory {
                request_id,
                username,
                ip,
            } => Self::send_register_to_server(server_urls, request_id, &username, &ip),
            ClientRequest::AddImage {
                request_id,
                username,
                image_name,
                image_bytes,
            } => {
                Self::send_add_image_to_server(
                    server_urls,
                    request_id,
                    &username,
                    &image_name,
                    &image_bytes,
                ) // ← Add this
            }
            ClientRequest::Heartbeat {
                request_id,
                username,
            } => Self::send_heartbeat_to_server(server_urls, request_id, &username),
            ClientRequest::FetchActiveUsers { request_id } => {
                Self::send_fetch_users_to_server(server_urls, request_id)
            }
            ClientRequest::FetchUserImages {
                request_id,
                target_username,
            } => Self::send_fetch_images_to_server(server_urls, request_id, &target_username),
            ClientRequest::RequestImageAccess {
                request_id,
                owner,
                viewer,
                image_name,
                prop_views,
            } => Self::send_request_access_to_server(
                server_urls,
                request_id,
                &owner,
                &viewer,
                &image_name,
                prop_views,
            ),
            ClientRequest::ViewPendingRequests {
                request_id,
                username,
            } => {
                match Self::send_view_pending_requests_to_server(server_urls, request_id, &username)
                {
                    Ok(requests) => {
                        // ✅ Serialize and store in output_path
                        let requests_json = serde_json::to_string(&requests).unwrap_or_default();
                        MiddlewareResponse::success(
                            request_id,
                            "Pending requests fetched successfully",
                            Some(requests_json),
                        )
                    }
                    Err(e) => MiddlewareResponse::error(request_id, &e),
                }
            }
            ClientRequest::ApproveOrRejectAccess {
                request_id,
                owner,
                viewer,
                image_name,
                accep_views,
            } => Self::send_approve_access_to_server(
                server_urls,
                request_id,
                &owner,
                &viewer,
                &image_name,
                accep_views,
            ),
            ClientRequest::GetAcceptedViews {
                request_id,
                owner,
                viewer,
                image_name,
            } => Self::send_get_accepted_views_to_server(
                server_urls,
                request_id,
                &owner,
                &viewer,
                &image_name,
            ),
        }
    }
    /// Send encryption request to ALL servers simultaneously
    /// Returns the FIRST successful response
    fn send_encrypt_to_multiple_servers(
        server_urls: &[String],
        request_id: u64,
        image_path: &str,
        views: HashMap<String, u64>, //VIEWS NEED TO CHANGE
    ) -> MiddlewareResponse {
        use std::fs;
        use std::path::Path;

        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Image file not found");
        }

        // Read file once (shared by all threads)
        let file_data = match fs::read(image_path) {
            Ok(data) => data,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to read file: {}", e),
                );
            }
        };

        let filename = Path::new(image_path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // === NEW: compute timeout based on image size ===
        // Base timeout: 60 seconds (was 30)
        let base_secs = 60u64;
        // Per-MB overhead: 20 seconds per MB (was 15)
        let per_mb_secs = 20u64;
        let size_bytes = file_data.len() as f64;
        let size_mb = size_bytes / (1024.0 * 1024.0);
        //let per_mb_secs: u64 = 20;
        let extra_mb = size_mb.ceil() as u64; // ceil(3.5) -> 4
        let timeout_secs = base_secs.saturating_add(extra_mb.saturating_mul(per_mb_secs));
        let timeout_duration = Duration::from_secs(timeout_secs);
        println!(
            "[ClientMiddleware] [Req #{}] Computed timeout: {} seconds (size: {:.2} MB → +{} MB * {}s/MB)",
            request_id, timeout_secs, size_mb, extra_mb, per_mb_secs
        );
        // ===============================================

        println!(
            "[ClientMiddleware] [Req #{}] Broadcasting to {} servers ({} bytes) ({:?} views) -> timeout: {}s",
            request_id,
            server_urls.len(),
            file_data.len(),
            views, //VIEWS NEED TO CHANGE
            timeout_secs
        );

        // Keep retrying until success
        loop {
            let start_time = Instant::now();
            let response: Arc<Mutex<Option<MiddlewareResponse>>> = Arc::new(Mutex::new(None));
            let mut handles = vec![];

            // Launch parallel requests to all servers
            for (index, server_url) in server_urls.iter().enumerate() {
                let server_url = server_url.clone();
                let file_data = file_data.clone();
                let filename = filename.clone();
                let response = Arc::clone(&response);
                let views = views.clone(); //VIEWS NEED TO CHANGE

                let handle = thread::spawn(move || {
                    println!(
                        "[ClientMiddleware] [Req #{}] [Server {}] Sending to {} ({:?} views)",
                        request_id,
                        index + 1,
                        server_url,
                        views //VIEWS NEED TO CHANGE
                    );

                    match Self::send_encrypt_to_single_server(
                        &server_url,
                        request_id,
                        &filename,
                        &file_data,
                        views, //VIEWS NEED TO CHANGE
                    ) {
                        Ok(server_response) => {
                            if server_response.status == "OK" {
                                let mut response_lock = response.lock().unwrap();
                                if response_lock.is_none() {
                                    println!(
                                        "[ClientMiddleware] [Req #{}] [Server {}] FIRST OK RESPONSE (Winner!)",
                                        request_id,
                                        index + 1
                                    );
                                    *response_lock = Some(server_response);
                                } else {
                                    println!(
                                        "[ClientMiddleware] [Req #{}] [Server {}] OK (but too late)",
                                        request_id,
                                        index + 1
                                    );
                                }
                            } else {
                                println!(
                                    "[ClientMiddleware] [Req #{}] [Server {}] Response not OK",
                                    request_id,
                                    index + 1
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[ClientMiddleware] [Req #{}] [Server {}] Failed: {}",
                                request_id,
                                index + 1,
                                e
                            );
                        }
                    }
                });

                handles.push(handle);
            }

            // Wait for threads or computed timeout
            while start_time.elapsed() < timeout_duration {
                {
                    let response_lock = response.lock().unwrap();
                    if let Some(resp) = response_lock.as_ref() {
                        println!(
                            "[ClientMiddleware] [Req #{}] Broadcasting complete - got response!",
                            request_id
                        );
                        return resp.clone();
                    }
                }
                thread::sleep(Duration::from_millis(500)); // check every 0.5s
            }

            // Timeout: no OK response
            println!(
                "[ClientMiddleware] [Req #{}] Timeout after {}s - retrying broadcast...",
                request_id, timeout_secs
            );

            // Make sure all threads finish cleanly before retry
            for handle in handles {
                let _ = handle.join();
            }

            // Wait briefly before retrying (optional)
            thread::sleep(Duration::from_secs(2));
        }
    }

    fn send_encrypt_to_single_server(
        server_url: &str,
        request_id: u64,
        filename: &str,
        file_data: &[u8],
        views: HashMap<String, u64>, //VIEWS NEED TO CHANGE
    ) -> Result<MiddlewareResponse, Box<dyn Error>> {
        // === NEW: compute client timeout consistently with outer logic ===
        let base_secs = 60u64;
        // Per-MB overhead: 20 seconds per MB (was 15)
        let per_mb_secs = 20u64;
        let size_bytes = file_data.len() as f64;
        let size_mb = size_bytes / (1024.0 * 1024.0);
        let per_mb_secs: u64 = 20;
        let extra_mb = size_mb.ceil() as u64;
        let timeout_secs = base_secs.saturating_add(extra_mb.saturating_mul(per_mb_secs));
        // ===============================================================

        // Create multipart form using reqwest blocking client
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_secs)) // use computed timeout
            .build()?;

        let url = format!("{}/encrypt", server_url);
        let views_json = serde_json::to_string(&views)?; //NEED TO SERIALIZE FIRST, DESERIALIZE SERVER SIDE
        let form = reqwest::blocking::multipart::Form::new()
            .text("request_id", request_id.to_string())
            .text("filename", filename.to_string())
            .text("views", views_json) //VIEWS NEED TO CHANGE
            .part(
                "file",
                reqwest::blocking::multipart::Part::bytes(file_data.to_vec())
                    .file_name(filename.to_string()),
            );

        // Send HTTP POST request
        let response = client.post(&url).multipart(form).send()?;

        // Parse response
        let server_resp: ServerResponse = response.json()?;

        if server_resp.status == "success" {
            // Save returned file if present
            if let (Some(file_data_b64), Some(output_filename)) =
                (&server_resp.file_data, &server_resp.output_filename)
            {
                let file_data = general_purpose::STANDARD.decode(file_data_b64)?;
                let output_dir = "client_storage";
                std::fs::create_dir_all(output_dir)?;
                let output_stem = Path::new(output_filename)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("output");
                let output_path = format!("{}/{}.png", output_dir, output_stem);
                std::fs::write(&output_path, file_data)?;

                // ✅ Return base64 data in output_path for post-approval workflow
                return Ok(MiddlewareResponse::success(
                    request_id,
                    &server_resp.message,
                    Some(file_data_b64.clone()), // ← Return base64 string here
                ));
            }

            Ok(MiddlewareResponse::success(
                request_id,
                &server_resp.message,
                server_resp.file_data.clone(), // ← Or this for consistency
            ))
        } else {
            Err(format!("Server returned error: {}", server_resp.message).into())
        }
    }
    fn extract_and_decrypt_views(
        png_path: &str,
        password_hex: &str, // same hex key used for encryption
    ) -> Result<HashMap<String, u64>, String> {
        // 1️⃣ Read the PNG
        let file = File::open(png_path).map_err(|e| format!("Failed to open PNG: {}", e))?;

        let decoder = Decoder::new(BufReader::new(file));

        let mut reader = decoder
            .read_info()
            .map_err(|e| format!("Failed to read PNG header: {}", e))?;

        let mut buf = vec![0; reader.output_buffer_size()];
        let _info = reader
            .next_frame(&mut buf)
            .map_err(|e| format!("Failed to read PNG frame: {}", e))?;

        // 2️⃣ Extract iTXt chunks
        let info = reader.info();

        let mut encoded_views_hex: Option<String> = None;

        for chunk in &info.utf8_text {
            if chunk.keyword == "EncryptedViews" {
                let text_str = chunk
                    .get_text()
                    .map_err(|e| format!("Failed to decode ITXt chunk: {}", e))?;
                encoded_views_hex = Some(text_str);
                break;
            }
        }

        let encoded_views_hex =
            encoded_views_hex.ok_or_else(|| "EncryptedViews iTXt chunk not found".to_string())?;

        // 3️⃣ Decode hex → nonce + ciphertext
        let full =
            hex::decode(encoded_views_hex).map_err(|e| format!("Hex decode error: {}", e))?;

        if full.len() < 24 {
            return Err("iTXt encrypted data too small".into());
        }

        let nonce_bytes = &full[..24];
        let ciphertext = &full[24..];

        let nonce = XNonce::from_slice(nonce_bytes);

        // 4️⃣ Key decode
        let key_bytes = hex::decode(password_hex).map_err(|e| format!("Invalid hex key: {}", e))?;

        let key = Key::from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new(key);

        // 5️⃣ Decrypt JSON
        let decrypted = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|e| format!("Decryption failed: {}", e))?;

        // 6️⃣ Deserialize back to HashMap<String,u64>
        let views: HashMap<String, u64> = serde_json::from_slice(&decrypted)
            .map_err(|e| format!("JSON deserialize error: {}", e))?;

        Ok(views)
    }
    // New local decryption function (dummy implementation)
    fn decrypt_image_locally(
        request_id: u64,
        image_path: &str,
        username: &str,
    ) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Encrypted file not found");
        }

        println!(
            "[ClientMiddleware] [Req #{}] Decrypting locally: {}",
            request_id, image_path
        );

        //DECRYPTION LOGIC NEEDED
        //EXTRACT VIEWS LIST
        let secret_key: &[u8] = b"supersecretkey_supersecretkey_32";
        let view_key = Key::from_slice(secret_key);
        let password_hex = hex::encode(view_key.as_slice());
        //let password_hex = hex::encode(view_key);
        //VIEWS EXTRACTED
        let mut parsed_views = match Self::extract_and_decrypt_views(image_path, &password_hex) {
            Ok(v) => v,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to extract/decrypt views: {}", e),
                );
            }
        };
        println!(
            "[ClientMiddleware] [Req #{}] Image Users and Views: {:?}",
            request_id, parsed_views
        );
        //CHECK IF WE CAN STILL VIEW (AGREE ON IMPLEMENTATION LATER)
        //CHECK IF WE CAN STILL VIEW (AGREE ON IMPLEMENTATION LATER)
        match parsed_views.get_mut(username) {
            Some(count) => {
                if *count == 0 {
                    return MiddlewareResponse::error(request_id, "Username Views Exceeded");
                }
                *count -= 1;
                println!("User: {} has {} views remaining", username, *count);
            }
            None => return MiddlewareResponse::error(request_id, "Username Not Found"),
        }

        let tmp_extract_dir = match tempfile::tempdir_in("/tmp") {
            Ok(dir) => dir,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to create temp folder: {}", e),
                );
            }
        };
        println!(
            "Temporary extraction folder: {}",
            tmp_extract_dir.path().display()
        );

        println!("[ClientMiddleware] [Req #{}] Decryption Begin", request_id);

        //let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let cipher = XChaCha20Poly1305::new(view_key);
        //VIEW ENCRYPTION SETUP
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        //VIEW ENCRYPTION LOGIC
        let json_bytes = match serde_json::to_vec(&parsed_views) {
            Ok(j) => j,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to Serialize Views: {}", e),
                );
            }
        };
        let ciphertext = match cipher.encrypt(
            &nonce,
            Payload {
                msg: &json_bytes,
                aad: &[],
            },
        ) {
            Ok(c) => c,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to Encrypt Views: {}", e),
                );
            }
        };
        let mut full = Vec::new();
        full.extend_from_slice(&nonce.as_slice());
        full.extend_from_slice(&ciphertext);
        let encoded_views = hex::encode(full);

        if let Err(e) = extract_prepare()
            .using_password(password_hex.as_str())
            .from_secret_file(image_path)
            .into_output_folder(tmp_extract_dir.path())
            .execute()
        {
            return MiddlewareResponse::error(
                request_id,
                &format!("Failed to extract hidden data: {}", e),
            );
        }

        println!("Extracted payload to {}", tmp_extract_dir.path().display());
        let extracted_file_path = match fs::read_dir(tmp_extract_dir.path()).and_then(|mut rd| {
            rd.next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "No extracted file found")
                })?
                .map(|e| e.path())
        }) {
            Ok(path) => path,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to locate extracted file: {}", e),
                );
            }
        };
        println!("Found extracted file: {}", extracted_file_path.display());
        let extracted_bytes = match fs::read(&extracted_file_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to read extracted file: {}", e),
                );
            }
        };
        println!("Extracted size: {} bytes", extracted_bytes.len());
        println!(
            "First 32 bytes: {:?}",
            &extracted_bytes[..32.min(extracted_bytes.len())]
        );

        let recovered: HiddenPayload = match bincode::deserialize(&extracted_bytes) {
            Ok(payload) => payload,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to deserialize payload: {}", e),
                );
            }
        };
        println!("Recovered message: {}", recovered.message);
        // if let Some(extra) = &recovered.extra {
        //     println!("Extra: {}", extra);
        // }
        let output_dir = PathBuf::from("client_storage");
        if let Err(e) = std::fs::create_dir_all(&output_dir) {
            return MiddlewareResponse::error(
                request_id,
                &format!("Failed to create directory: {}", e),
            );
        }

        //fs::create_dir_all(&output_dir)?;
        let output_stem = Path::new(image_path)
            .file_stem() // e.g. "encrypted_input"
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let output_path = output_dir.join(format!("decrypted_{}.png", output_stem));

        match fs::write(&output_path, &recovered.image_bytes) {
            Ok(_) => {
                let file = match File::open(&image_path) {
                    Ok(f) => f,
                    Err(e) => {
                        return MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to Open Original Image: {}", e),
                        );
                    }
                };
                let decoder = Decoder::new(BufReader::new(file));
                let mut reader = match decoder.read_info() {
                    Ok(r) => r,
                    Err(e) => {
                        return MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to Read Original Image Info: {}", e),
                        );
                    }
                };
                let mut buf = vec![0; reader.output_buffer_size()];
                let info = match reader.next_frame(&mut buf) {
                    Ok(i) => i,
                    Err(e) => {
                        return MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to Match Buffer: {}", e),
                        );
                    }
                };
                buf.truncate(info.buffer_size());
                let out_tmp = Path::new(image_path).with_extension("tmp.png");
                // Re-encode with a new iTXt chunk
                let out = match File::create(&out_tmp) {
                    Ok(f) => f,
                    Err(e) => {
                        return MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to Write to Original Image: {}", e),
                        );
                    }
                };
                let w = BufWriter::new(out);

                let mut encoder = Encoder::new(w, info.width, info.height);
                encoder.set_color(info.color_type);
                encoder.set_depth(info.bit_depth);

                if let Err(e) =
                    encoder.add_itxt_chunk("EncryptedViews".to_string(), encoded_views.clone())
                {
                    return MiddlewareResponse::error(
                        request_id,
                        &format!("Failed to Add ITXT Chunk: {}", e),
                    );
                }

                let mut writer = match encoder.write_header() {
                    Ok(w) => w,
                    Err(e) => {
                        return MiddlewareResponse::error(
                            request_id,
                            &format!("Failed to Write Header: {}", e),
                        );
                    }
                };
                // Write PNG image data
                if let Err(e) = writer.write_image_data(&buf) {
                    return MiddlewareResponse::error(
                        request_id,
                        &format!("Failed to Write PNG data: {}", e),
                    );
                }

                // Finish writing
                if let Err(e) = writer.finish() {
                    return MiddlewareResponse::error(
                        request_id,
                        &format!("Failed to Finish Writing: {}", e),
                    );
                }
                if let Err(e) = std::fs::rename(&out_tmp, &image_path) {
                    // try best-effort cleanup
                    let _ = std::fs::remove_file(&out_tmp);
                    return MiddlewareResponse::error(
                        request_id,
                        &format!("Failed to replace output file: {}", e),
                    );
                }
                println!(
                    "[ClientMiddleware] [Req #{}] Decryption complete → saved hidden image as: {} -> Updated Views: {:?}",
                    request_id,
                    output_path.display(),
                    parsed_views
                );
                MiddlewareResponse::success(
                    request_id,
                    &format!(
                        "Image successfully decrypted and saved to {}",
                        output_path.display()
                    ),
                    Some(output_path.to_string_lossy().to_string()),
                )
            }
            Err(e) => {
                eprintln!(
                    "[ClientMiddleware] [Req #{}] Failed to save decrypted image: {}",
                    request_id, e
                );
                MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to save decrypted image: {}", e),
                )
            }
        }
    }
    fn send_register_to_server(
        server_urls: &[String],
        request_id: u64,
        username: &str,
        ip: &str,
    ) -> MiddlewareResponse {
        println!(
            "[ClientMiddleware] [Req #{}] Forwarding registration to server: {} {}",
            request_id, username, ip
        );

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        // Try first available server
        let server_url = &server_urls[0];
        let url = format!("{}/register", server_url);

        let payload = serde_json::json!({
            "request_id": request_id,
            "username": username,
            "ip": ip,
        });

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<ServerResponse>() {
                Ok(server_resp) => {
                    if server_resp.status == "success" {
                        MiddlewareResponse::success(request_id, &server_resp.message, None)
                    } else {
                        MiddlewareResponse::error(request_id, &server_resp.message)
                    }
                }
                Err(e) => MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to parse response: {}", e),
                ),
            },
            Err(e) => {
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }
    fn send_add_image_to_server(
        server_urls: &[String],
        request_id: u64,
        username: &str,
        image_name: &str,
        image_bytes: &[u8],
    ) -> MiddlewareResponse {
        println!(
            "[ClientMiddleware] [Req #{}] Forwarding add image to server: {} {} ({} bytes)",
            request_id,
            username,
            image_name,
            image_bytes.len()
        );

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        // Try first available server
        let server_url = &server_urls[0];
        let url = format!("{}/add_image", server_url);

        // Encode image data as base64 for JSON transport
        let image_bytes_b64 = general_purpose::STANDARD.encode(image_bytes);

        let payload = serde_json::json!({
            "request_id": request_id,
            "username": username,
            "image_name": image_name,
            "image_bytes": image_bytes_b64,
        });

        match client.post(&url).json(&payload).send() {
            Ok(response) => match response.json::<ServerResponse>() {
                Ok(server_resp) => {
                    if server_resp.status == "success" {
                        MiddlewareResponse::success(request_id, &server_resp.message, None)
                    } else {
                        MiddlewareResponse::error(request_id, &server_resp.message)
                    }
                }
                Err(e) => MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to parse response: {}", e),
                ),
            },
            Err(e) => {
                MiddlewareResponse::error(request_id, &format!("Failed to contact server: {}", e))
            }
        }
    }
}
