use base64::{Engine as _, engine::general_purpose};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use std::error::Error;

const DIRECTORY_URL: &str = "http://127.0.0.1:5000/api";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAccessRequest {
    pub viewer: String,
    pub image_name: String,
    pub prop_views: u64,
}

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

        let is_online = body["is_online"].as_bool().unwrap_or(false);

        println!("[Directory Service] is_online: {}", is_online);

        // Parse images from response: Vec<(image_name, image_bytes_base64)>
        if let Some(images_array) = body["images"].as_array() {
            let images: Vec<(String, String)> = images_array
                .iter()
                .filter_map(|img| {
                    let name = img["image_name"].as_str()?.to_string();
                    let bytes_b64 = img["image_bytes"].as_str()?.to_string();
                    Some((name, bytes_b64))
                })
                .collect();

            Ok((is_online, images))
        } else {
            println!("[Directory Service] No images array found");
            Ok((is_online, Vec::new()))
        }
    } else {
        Err(format!("Fetch images failed with status: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------

pub async fn request_image_access(
    owner: &str,
    viewer: &str,
    image_name: &str,
    prop_views: u64,
) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "request_image_access",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
        "prop_views": prop_views,
    });

    println!(
        "[Directory Service] Requesting access: {} wants {} views of {}'s '{}'",
        viewer, prop_views, owner, image_name
    );

    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        let body: Value = response.json().await?;
        println!("[Directory Service] ✓ Access request created: {:?}", body);
        Ok(())
    } else {
        Err(format!("Access request failed with status: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------

pub async fn get_pending_access_requests(
    username: &str,
) -> Result<Vec<PendingAccessRequest>, Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "get_pending_requests",
        "user_name": username,
    });

    println!(
        "[Directory Service] Fetching pending access requests for: {}",
        username
    );

    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        let body: Value = response.json().await?;

        let mut requests = Vec::new();

        if let Some(requests_array) = body["requests"].as_array() {
            for req in requests_array {
                let viewer = req["viewer"].as_str().unwrap_or("").to_string();
                let image_name = req["image_name"].as_str().unwrap_or("").to_string();
                let prop_views = req["prop_views"].as_u64().unwrap_or(0);

                requests.push(PendingAccessRequest {
                    viewer,
                    image_name,
                    prop_views,
                });
            }
        }

        Ok(requests)
    } else {
        Err(format!("Failed to fetch pending requests: {}", response.status()).into())
    }
}

// ------------------------------------------------------------------------------------

pub async fn approve_or_reject_access_request(
    owner: &str,
    viewer: &str,
    image_name: &str,
    accep_views: i64, // Can be -1 for reject
) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    let payload = json!({
        "operation": "approve_or_reject_access",
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
        "[Directory Service] {} access: {} -> {}'s '{}' ({} views)",
        action, viewer, owner, image_name, accep_views
    );

    let response = client.post(DIRECTORY_URL).json(&payload).send().await?;

    if response.status().is_success() {
        let body: Value = response.json().await?;
        println!("[Directory Service] ✓ Access request updated: {:?}", body);
        Ok(())
    } else {
        Err(format!("Failed to update access request: {}", response.status()).into())
    }
}
