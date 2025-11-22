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

pub async fn update_client_timestamp(username: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "update_timestamp",
        "user_name": username,
    });

    // Send request asynchronously
    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Timestamp update failed with status: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------

pub async fn fetch_active_users() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "fetch_active_users",
    });

    // Send request asynchronously
    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        let body: Value = response.json().await?;

        // Parse users from response
        if let Some(users_array) = body["users"].as_array() {
            let users: Vec<(String, String)> = users_array
                .iter()
                .filter_map(|user| {
                    let username = user["user_name"].as_str()?.to_string();
                    let ip = user["ip_addr"].as_str()?.to_string();
                    Some((username, ip))
                })
                .collect();
            Ok(users)
        } else {
            Ok(Vec::new())
        }
    } else {
        Err(format!("Fetch users failed with status: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------

pub async fn fetch_user_images(
    username: &str,
) -> Result<(bool, Vec<(String, String)>), Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "fetch_user_images",
        "user_name": username,
    });

    println!("[Directory Service] Sending request for user: {}", username);

    // Send request asynchronously
    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    println!(
        "[Directory Service] Got response status: {}",
        response.status()
    );

    if response.status().is_success() {
        let body: Value = response.json().await?;

        println!("[Directory Service] Response body: {:?}", body);

        let is_online = body["is_online"].as_bool().unwrap_or(false);

        println!("[Directory Service] is_online: {}", is_online);

        // Parse images from response: Vec<(image_name, image_bytes_base64)>
        if let Some(images_array) = body["images"].as_array() {
            println!(
                "[Directory Service] Images array length: {}",
                images_array.len()
            );

            let images: Vec<(String, String)> = images_array
                .iter()
                .filter_map(|img| {
                    let name = img["image_name"].as_str()?.to_string();
                    let bytes_b64 = img["image_bytes"].as_str()?.to_string();
                    Some((name, bytes_b64))
                })
                .collect();

            println!("[Directory Service] Parsed {} images", images.len());

            Ok((is_online, images))
        } else {
            println!("[Directory Service] No images array found");
            Ok((is_online, Vec::new()))
        }
    } else {
        Err(format!("Fetch images failed with status: {}", response.status()).into())
    }
}
