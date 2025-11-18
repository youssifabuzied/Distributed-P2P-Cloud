use base64::{Engine as _, engine::general_purpose};
use bincode;
use hex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use stegano_core::api::unveil::prepare as extract_prepare;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce, Key
};
use png::{Encoder, Decoder};
use png::text_metadata::{ITXtChunk};
use std::fs::File;


#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest { //VIEWS NEED TO CHANGE
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
}
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload { //VIEWS NEED TO CHANGE + VIEWS NO LONGER IN PAYLOAD!!!!
    message: String,
    // views: HashMap<String, u64>,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    // extra: Option<String>,
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
fn extract_and_decrypt_views(
    png_path: &str,
    password_hex: &str,   // same hex key used for encryption
    ) -> Result<HashMap<String, u64>, String> {
        // 1️⃣ Read the PNG
        let file = File::open(png_path)
            .map_err(|e| format!("Failed to open PNG: {}", e))?;

        let decoder = Decoder::new(BufReader::new(file));

        let mut reader = decoder.read_info()
            .map_err(|e| format!("Failed to read PNG header: {}", e))?;

        let mut buf = vec![0; reader.output_buffer_size()];
        let _info = reader.next_frame(&mut buf)
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
        let full = hex::decode(encoded_views_hex)
            .map_err(|e| format!("Hex decode error: {}", e))?;

        if full.len() < 24 {
            return Err("iTXt encrypted data too small".into());
        }

        let nonce_bytes = &full[..24];
        let ciphertext = &full[24..];

        let nonce = XNonce::from_slice(nonce_bytes);

        // 4️⃣ Key decode
        let key_bytes =
            hex::decode(password_hex).map_err(|e| format!("Invalid hex key: {}", e))?;

        let key = Key::from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new(key);

        // 5️⃣ Decrypt JSON
        let decrypted = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] })
            .map_err(|e| format!("Decryption failed: {}", e))?;

        // 6️⃣ Deserialize back to HashMap<String,u64>
        let views: HashMap<String, u64> =
            serde_json::from_slice(&decrypted)
            .map_err(|e| format!("JSON deserialize error: {}", e))?;

        Ok(views)
    }
fn decrypt_image_locally(request_id: u64, image_path: &str, username: &str) -> MiddlewareResponse {
        // Validate file exists
        if !Path::new(image_path).exists() {
            return MiddlewareResponse::error(request_id, "Encrypted file not found");
        }

        println!(
            "[ClientMiddleware] [Req #{}] Decrypting locally: {}",
            request_id, image_path
        );
        let secret_key: &[u8] = b"supersecretkey_supersecretkey_32";
        let view_key = Key::from_slice(secret_key);
        let password_hex = hex::encode(view_key.as_slice());
        //let password_hex = hex::encode(view_key);
        //VIEWS EXTRACTED
        let mut parsed_views = match extract_and_decrypt_views(image_path, &password_hex) {
            Ok(v) => v,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to extract/decrypt views: {}", e),
                )
            }
        };

        println!(
            "[ClientMiddleware] [Req #{}] Image Users and Views: {:?}",
            request_id, parsed_views
        );
        //CHECK IF WE CAN STILL VIEW (AGREE ON IMPLEMENTATION LATER)
        match parsed_views.get_mut(username) {
            Some(count) => {
                if *count == 0 {
                    return MiddlewareResponse::error(request_id, "Username Views Exceeded");
                }
                *count -= 1;
                println!("User {} has {} views remaining", username, *count);
            }
            None => return MiddlewareResponse::error(request_id, "Username Not Found"),
        }
        
        //DECREMENT VIEW COUNT IF ALLOWED
        //RETURN ERROR IF NOT ALLOWED
        //CHANGE PAYLOAD TO REFLECT NEW VIEW COUNT
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
        //let json = serde_json::to_vec(&parsed_views);
        let json_bytes = match serde_json::to_vec(&parsed_views) {
            Ok(j) => j,
            Err(e) => {
                return MiddlewareResponse::error(
                    request_id,
                    &format!("Failed to Serialize Views: {}", e),
                );
            }
        };
        let ciphertext = match cipher.encrypt(&nonce, Payload { msg: &json_bytes, aad: &[] }) {
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
        let encoded_views=hex::encode(full);
        
        
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
                Err(e) =>{
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

            if let Err(e) = encoder.add_itxt_chunk(
                "EncryptedViews".to_string(),
                encoded_views.clone(),
            ) {
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
fn main() {
    let image_path = "client_storage/output.png"; // <-- replace with your encrypted image
    let res = decrypt_image_locally(42, image_path,"user1");

    println!("\n==== Result ====");
    println!("Status: {}", res.status);
    println!("Message: {}", res.message.as_deref().unwrap_or("None"));

    if let Some(p) = res.output_path {
        println!("Saved as: {}", p);
    }
}