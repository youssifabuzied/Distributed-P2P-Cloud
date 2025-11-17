use base64::{Engine as _, engine::general_purpose};
use reqwest::Client;
use serde_json::Value;
use serde_json::json;
use std::error::Error;

const DIRECTORY_URL: &str = "http://127.0.0.1:5000/api";

// ------------------------------------------------------------------------------------

pub async fn register_client(username: &str, ip: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "add_client",
        "user_name": username,
        "ip_addr": ip,
    });

    println!(
        "[Directory Service] Registering client: {} {}",
        username, ip
    );

    // Send request asynchronously
    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        let body: Value = response.json().await?;
        println!("[Directory Service] ✓ Registration successful: {:?}", body);
        Ok(())
    } else {
        Err(format!("Registration failed with status: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------

pub async fn add_image(
    username: &str,
    image_name: &str,
    image_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    // Encode image data as base64 for JSON transport
    let image_bytes_b64 = base64::engine::general_purpose::STANDARD.encode(image_bytes);

    let payload = json!({
        "operation": "add_image",
        "user_name": username,
        "image_name": image_name,
        "image_bytes": image_bytes_b64,
    });

    println!(
        "[Directory Service] Adding image: {} for user {} ({} bytes)",
        image_name,
        username,
        image_bytes.len()
    );

    // Send request asynchronously
    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        let body: Value = response.json().await?;
        println!("[Directory Service] ✓ Image added successfully: {:?}", body);
        Ok(())
    } else {
        Err(format!("Add image failed with status: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------
