use base64::{Engine as _, engine::general_purpose};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::error::Error;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

use once_cell::sync::Lazy;
use std::fs;

pub static DIRECTORY_URLS: Lazy<Vec<String>> = Lazy::new(|| {
    // Read server URLs from JSON once at startup
    let urls: Vec<String> = if let Ok(text) = fs::read_to_string("server/database_urls.json") {
        serde_json::from_str(&text).unwrap_or_else(|_| {
            eprintln!("Failed to parse server_urls.json");
            Vec::new()
        })
    } else {
        eprintln!("Failed to read server_urls.json");
        Vec::new()
    };

    // Append `/api` to match the previous DIRECTORY_URLS
    urls.into_iter().map(|u| format!("{}/api", u)).collect()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAccessRequest {
    pub viewer: String,
    pub image_name: String,
    pub prop_views: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdditionalViewsRequest {
    pub viewer: String,
    pub image_name: String,
    pub prop_views: u64,
    pub accep_views: u64,
}

// ------------------------------ Option B helpers ------------------------------

async fn write_to_all_databases(
    operation: &str,
    payload: &Value,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = Arc::new(Client::new());
    let (tx, rx) = oneshot::channel();
    let tx = Arc::new(Mutex::new(Some(tx)));

    for url in DIRECTORY_URLS.iter() {
        let client_clone = Arc::clone(&client);
        let tx_clone = Arc::clone(&tx);
        let payload_clone = payload.clone();
        let url_clone = url.to_string();
        let operation_clone = operation.to_string();

        tokio::spawn(async move {
            match client_clone
                .post(&url_clone)
                .json(&payload_clone)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    // First success wins
                    if let Some(sender) = tx_clone.lock().unwrap().take() {
                        let _ = sender.send(Ok(()));
                    }
                }
                Ok(_) => {
                    eprintln!("[Directory Service] {} responded with error", url_clone);
                }
                Err(e) => {
                    eprintln!("[Directory Service] {} failed: {}", url_clone, e);
                }
            }
        });
    }

    match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(format!("All databases failed for operation: {}", operation).into()),
        Err(_) => Err(format!("Database request timeout for operation: {}", operation).into()),
    }
}
use tokio::sync::oneshot;

async fn read_from_one_database<T, F>(
    operation: &str,
    payload: &Value,
    parse_response: F,
) -> Result<T, Box<dyn Error + Send + Sync>>
where
    T: Send + 'static,
    F: Fn(Value) -> Result<T, String> + Send + Sync + 'static,
{
    let (tx, rx) = oneshot::channel();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let parse_fn = Arc::new(parse_response);
    let client = Arc::new(Client::new());

    for url in DIRECTORY_URLS.iter() {
        let tx_clone = Arc::clone(&tx);
        let parse_fn_clone = Arc::clone(&parse_fn);
        let client_clone = Arc::clone(&client);
        let payload_clone = payload.clone();
        let url_clone = url.to_string();
        let operation_clone = operation.to_string();

        tokio::spawn(async move {
            match client_clone
                .post(&url_clone)
                .json(&payload_clone)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    if let Ok(body) = response.json::<Value>().await {
                        if let Ok(result) = parse_fn_clone(body) {
                            if let Some(sender) = tx_clone.lock().unwrap().take() {
                                let _ = sender.send(Ok(result));
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[Directory Service] Read {} failed from {}: {}",
                        operation_clone, url_clone, e
                    );
                }
                _ => {}
            }
        });
    }

    match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(format!("All databases failed for operation: {}", operation).into()),
        Err(_) => Err(format!("Database request timeout for operation: {}", operation).into()),
    }
}

// ------------------------------ Public API ------------------------------

pub async fn register_client(username: &str, ip: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "add_client",
        "user_name": username,
        "ip_addr": ip,
    });

    println!(
        "[Directory Service] Registering client: {} {} (writing to {} databases)",
        username,
        ip,
        DIRECTORY_URLS.len()
    );

    write_to_all_databases("add_client", &payload).await
}

pub async fn add_image(
    username: &str,
    image_name: &str,
    image_bytes: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let image_bytes_b64 = general_purpose::STANDARD.encode(image_bytes);
    let payload = json!({
        "operation": "add_image",
        "user_name": username,
        "image_name": image_name,
        "image_bytes": image_bytes_b64,
    });

    println!(
        "[Directory Service] Adding image: {} for user {} ({} bytes) to {} databases",
        image_name,
        username,
        image_bytes.len(),
        DIRECTORY_URLS.len()
    );

    write_to_all_databases("add_image", &payload).await
}

pub async fn update_client_timestamp(username: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "update_timestamp",
        "user_name": username,
    });

    write_to_all_databases("update_timestamp", &payload).await
}

pub async fn fetch_active_users() -> Result<Vec<(String, String)>, Box<dyn Error + Send + Sync>> {
    let payload = json!({ "operation": "fetch_active_users" });
    read_from_one_database("fetch_active_users", &payload, |body| {
        if let Some(users_array) = body["users"].as_array() {
            let users: Vec<(String, String)> = users_array
                .iter()
                .filter_map(|user| {
                    Some((
                        user["user_name"].as_str()?.to_string(),
                        user["ip_addr"].as_str()?.to_string(),
                    ))
                })
                .collect();
            Ok(users)
        } else {
            Ok(Vec::new())
        }
    })
    .await
}

pub async fn fetch_user_images(
    username: &str,
) -> Result<(bool, Vec<(String, String)>), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "fetch_user_images",
        "user_name": username,
    });

    println!(
        "[Directory Service] Sending request for user: {} to one database",
        username
    );

    read_from_one_database("fetch_user_images", &payload, |body| {
        let is_online = body["is_online"].as_bool().unwrap_or(false);
        if let Some(images_array) = body["images"].as_array() {
            let images: Vec<(String, String)> = images_array
                .iter()
                .filter_map(|img| {
                    Some((
                        img["image_name"].as_str()?.to_string(),
                        img["image_bytes"].as_str()?.to_string(),
                    ))
                })
                .collect();
            Ok((is_online, images))
        } else {
            Ok((is_online, Vec::new()))
        }
    })
    .await
}

pub async fn request_image_access(
    owner: &str,
    viewer: &str,
    image_name: &str,
    prop_views: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "request_image_access",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
        "prop_views": prop_views,
    });

    println!(
        "[Directory Service] Requesting access: {} wants {} views of {}'s '{}' to {} databases",
        viewer,
        prop_views,
        owner,
        image_name,
        DIRECTORY_URLS.len()
    );

    write_to_all_databases("request_image_access", &payload).await
}

pub async fn get_pending_access_requests(
    username: &str,
) -> Result<Vec<PendingAccessRequest>, Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "get_pending_requests",
        "user_name": username,
    });

    read_from_one_database("get_pending_requests", &payload, |body| {
        let mut requests = Vec::new();
        if let Some(reqs) = body["requests"].as_array() {
            for r in reqs {
                requests.push(PendingAccessRequest {
                    viewer: r["viewer"].as_str().ok_or("Missing viewer")?.to_string(),
                    image_name: r["image_name"]
                        .as_str()
                        .ok_or("Missing image_name")?
                        .to_string(),
                    prop_views: r["prop_views"].as_u64().ok_or("Missing prop_views")?,
                });
            }
        }
        Ok(requests)
    })
    .await
}

pub async fn approve_or_reject_access_request(
    owner: &str,
    viewer: &str,
    image_name: &str,
    accep_views: i64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "approve_or_reject_access",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
        "accep_views": accep_views,
    });

    println!(
        "[Directory Service] {} access: {} -> {}'s '{}' ({} views) to {} databases",
        if accep_views == -1 {
            "Rejecting"
        } else {
            "Approving"
        },
        viewer,
        owner,
        image_name,
        accep_views,
        DIRECTORY_URLS.len()
    );

    write_to_all_databases("approve_or_reject_access", &payload).await
}

pub async fn get_accepted_views(
    owner: &str,
    viewer: &str,
    image_name: &str,
) -> Result<(bool, Option<u64>, String), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "get_accepted_views",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
    });

    read_from_one_database("get_accepted_views", &payload, |body| {
        let status = body["status"].as_str().unwrap_or("error");
        let message = body["message"]
            .as_str()
            .unwrap_or("Unknown error")
            .to_string();
        let accep_views = body["accep_views"].as_u64();

        if status == "success" {
            Ok((true, accep_views, message))
        } else {
            Ok((false, accep_views, message))
        }
    })
    .await
}

pub async fn modify_accepted_views(
    owner: &str,
    viewer: &str,
    image_name: &str,
    change_views: i64,
) -> Result<(bool, Option<u64>, String), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "modify_accepted_views",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
        "change_views": change_views,
    });

    write_to_all_databases("modify_accepted_views", &payload).await?;
    get_accepted_views(owner, viewer, image_name).await
}

pub async fn request_additional_views(
    owner: &str,
    viewer: &str,
    image_name: &str,
    additional_views: u64,
) -> Result<(bool, Option<u64>, String), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "request_additional_views",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
        "additional_views": additional_views,
    });

    write_to_all_databases("request_additional_views", &payload).await?;
    get_accepted_views(owner, viewer, image_name).await
}

pub async fn get_additional_views_requests(
    username: &str,
) -> Result<Vec<AdditionalViewsRequest>, Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "get_additional_views_requests",
        "user_name": username,
    });

    read_from_one_database("get_additional_views_requests", &payload, |body| {
        let mut requests = Vec::new();
        if let Some(arr) = body["requests"].as_array() {
            for r in arr {
                requests.push(AdditionalViewsRequest {
                    viewer: r["viewer"].as_str().ok_or("Missing viewer")?.to_string(),
                    image_name: r["image_name"]
                        .as_str()
                        .ok_or("Missing image_name")?
                        .to_string(),
                    prop_views: r["prop_views"].as_u64().ok_or("Missing prop_views")?,
                    accep_views: r["accep_views"].as_u64().ok_or("Missing accep_views")?,
                });
            }
        }
        Ok(requests)
    })
    .await
}

pub async fn accept_or_reject_additional_views(
    owner: &str,
    viewer: &str,
    image_name: &str,
    result: i32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = json!({
        "operation": "accept_or_reject_additional_views",
        "owner": owner,
        "viewer": viewer,
        "image_name": image_name,
        "result": result,
    });

    println!(
        "[Directory Service] {} additional views: {} -> {}'s '{}' to {} databases",
        if result == 0 {
            "Rejecting"
        } else {
            "Accepting"
        },
        viewer,
        owner,
        image_name,
        DIRECTORY_URLS.len()
    );

    write_to_all_databases("accept_or_reject_additional_views", &payload).await
}
