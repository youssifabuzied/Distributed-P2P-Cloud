use std::path::Path;
use aes_gcm::{Aes256Gcm, Key};
use hex;
//use tempfile::Builder;
use bincode;
use stegano_core::api::unveil::prepare as extract_prepare;
use std::{fs};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    message: String,
    views: i32,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    extra: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MiddlewareResponse {
    pub request_id: u64,
    pub status: String,
    pub message: Option<String>,
    pub output_path: Option<String>,
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
fn decrypt_image_locally(request_id: u64, image_path: &str) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Encrypted file not found");
        }

        println!("[ClientMiddleware] [Req #{}] Decrypting locally: {}", request_id, image_path);

        let tmp_extract_dir = match tempfile::tempdir_in("/tmp") {
            Ok(dir) => dir,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to create temp folder: {}", e),
                );
            }
        };
        println!("Temporary extraction folder: {}", tmp_extract_dir.path().display());

        //println!("[ClientMiddleware] [Req #{}] Read {} bytes", request_id, file_data.len());

        let secret_key = b"supersecretkey_supersecretkey_32";
        let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(key);
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
        let extracted_file_path = match fs::read_dir(tmp_extract_dir.path())
            .and_then(|mut rd| rd.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No extracted file found")
            })?.map(|e| e.path()))
        {
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
        println!("First 32 bytes: {:?}", &extracted_bytes[..32.min(extracted_bytes.len())]);

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
        println!("Views: {}", recovered.views);
        if let Some(extra) = &recovered.extra {
            println!("Extra: {}", extra);
        }
        let output_path = format!("{}_recovered.png", image_path);
        match fs::write(&output_path, &recovered.image_bytes) {
            Ok(_) => {
                println!(
                    "[ClientMiddleware] [Req #{}] Decryption complete → saved hidden image as: {}",
                    request_id, output_path
                );
                MiddlewareResponse::success(
                    request_id,
                    &format!("Image successfully decrypted and saved to {}", output_path),
                    Some(output_path),
                )
            }
            Err(e) => MiddlewareResponse::error(
                request_id,
                &format!("Failed to save recovered image: {}", e),
            ),
        }
    }
fn main() {
    let image_path = "../resources/extracted_payloads.png"; // <-- replace with your encrypted image
    let res = decrypt_image_locally(42, image_path);

    println!("\n==== Result ====");
    println!("Status: {}", res.status);
    println!("Message: {}", res.message.as_deref().unwrap_or("None"));

    if let Some(p) = res.output_path {
        println!("Saved as: {}", p);
    }
}