use aes_gcm::{Aes256Gcm, Key};
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
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};
use png::{Encoder, Decoder, TextChunk};
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
    fn decrypt_image_locally(request_id: u64, image_path: &str, username: &str) -> MiddlewareResponse {
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
        let decoder = Decoder::new(File::open(image_path));
        let mut reader = decoder.read_info();
        let mut encrypted = None;
        for chunk in reader.info().uncompressed_latin1_text.iter() {
            if chunk.keyword == "EncryptedViews" {
                encrypted = Some(chunk.text.clone());
            }
        }
        for chunk in reader.info().utf8_text.iter() {
            if chunk.keyword == "EncryptedViews" {
                encrypted = Some(chunk.text.clone());
            }
        }
        for chunk in reader.info().compressed_latin1_text.iter() {
            if chunk.keyword == "EncryptedViews" {
                encrypted = Some(chunk.text.clone());
            }
        }
        let encrypted = encrypted.ok_or("EncryptedViews chunk not found");
        let secret_key = b"supersecretkey_supersecretkey_32";
        let view_key = Key::<XChaCha20Poly1305>::from_slice(secret_key);
        let cipher = XChaCha20Poly1305::new(&view_key);

        let decoded_views = hex::decode(encrypted);
        let (nonce_bytes, ciphertext) = decoded_views.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] });
        //VIEWS EXTRACTED
        let parsed_views: HashMap<String, u64> = serde_json::from_slice(&plaintext);
        println!(
            "[ClientMiddleware] [Req #{}] Image Users and Views: {:?}",
            request_id, parsed_views
        );
        //CHECK IF WE CAN STILL VIEW (AGREE ON IMPLEMENTATION LATER)
        if let Some(count) = parsed_views.get(username) {
            if *count == 0 {
                return Ok(MiddlewareResponse::error(request_id, "Username Views Exceeded"));
            }
            *count -= 1;
            // User exists and has views
            println!("User {} has {} views remaining", username, *count);
        } else {
            // Username not found
            return Ok(MiddlewareResponse::error(request_id, "Username Not Found"));
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
        let password_hex = hex::encode(view_key);

        //VIEW ENCRYPTION SETUP
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        //VIEW ENCRYPTION LOGIC
        let json = serde_json::to_vec(&parsed_views);
        let ciphertext = cipher.encrypt(nonce, Payload { msg: &json, aad: &[] });
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
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
                println!(
                    "[ClientMiddleware] [Req #{}] Decryption complete → saved hidden image as: {}",
                    request_id,
                    output_path.display()
                );
                //EMBED UPDATED VIEWS INTO IMAGE
                let file = File::open(output_path);
                let decoder = Decoder::new(BufReader::new(file));
                let mut reader = decoder.read_info();
                let mut buf = vec![0; reader.output_buffer_size()];
                let info = reader.next_frame(&mut buf);
                buf.truncate(info.buffer_size());

                // Re-encode with a new iTXt chunk
                let out = File::create(output_path);
                let w = BufWriter::new(out);

                let mut encoder = Encoder::new(w, info.width, info.height);
                encoder.set_color(info.color_type);
                encoder.set_depth(info.bit_depth);

                let mut writer = encoder.write_header();

                writer.write_text_chunk(TextChunk::InternationalText {
                    keyword: "EncryptedViews".into(),
                    language_tag: "".into(),
                    translated_keyword: "".into(),
                    text: encoded_views.into(),
                    compressed: false,
                });

                writer.write_image_data(&buf);
                writer.finish();
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
    let image_path = "../resources/extracted_payloads.png"; // <-- replace with your encrypted image
    let res = decrypt_image_locally(42, image_path);

    println!("\n==== Result ====");
    println!("Status: {}", res.status);
    println!("Message: {}", res.message.as_deref().unwrap_or("None"));

    if let Some(p) = res.output_path {
        println!("Saved as: {}", p);
    }
}