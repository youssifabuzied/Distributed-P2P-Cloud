use std::{fs, error::Error, path::PathBuf};
use serde::{Serialize, Deserialize};
use std::io::{Write};
use std::env;
use image::io::Reader as ImageReader;
use image::{DynamicImage, ImageFormat,GenericImageView};
use image::imageops::FilterType;
use hex;
use aes_gcm::{Aes256Gcm, Key};
use bincode;
use std::io::Cursor;
use stegano_core::api::hide::prepare as hide_prepare;
use stegano_core::api::unveil::prepare as extract_prepare;
use tempfile::Builder;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionRequest {
    pub request_id: u64,
    pub filename: String,
    pub file_data: Vec<u8>,  // Raw image bytes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionResponse {
    pub request_id: u64,
    pub status: String,
    pub message: String,
    pub encrypted_data: Option<Vec<u8>>,
    pub original_size: usize,
    pub encrypted_size: usize,
}
#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    message: String,
    views: i32,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    extra: Option<String>,
}
    fn encrypt_data(request: EncryptionRequest) -> EncryptionResponse {

        println!("[Server] [Req #{}] Starting encryption...", request.request_id);
        let tmp_dir = PathBuf::from("/tmp/");
        if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        return EncryptionResponse {
            request_id: request.request_id,
            status: "error".into(),
            message: format!("Failed to create tmp dir: {}", e),
            encrypted_data: None,
            original_size: request.file_data.len(),
            encrypted_size: 0,
        };
        }

        let payload = HiddenPayload {
        message: format!("Hidden from file: {}", request.filename),
        views: 42,
        image_bytes: request.file_data.clone(),
        extra: Some("Metadata info".to_string()),
        };

        let serialized = match bincode::serialize(&payload) {
        Ok(s) => s,
        Err(e) => {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to serialize payload: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }
        };

        let cover_image_path = PathBuf::from("../resources/default_image.png");
        //let output_path = PathBuf::from("../resources/output_stego.png");

        let mut tmp_payload = match tempfile::NamedTempFile::new_in(&tmp_dir) {
        Ok(f) => f,
        Err(e) => {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to create tmp payload file: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }
        };
        if let Err(e) = tmp_payload.write_all(&serialized).and_then(|_| tmp_payload.flush()) {
        return EncryptionResponse {
            request_id: request.request_id,
            status: "error".into(),
            message: format!("Failed to write tmp payload: {}", e),
            encrypted_data: None,
            original_size: request.file_data.len(),
            encrypted_size: 0,
        };
        }
        let cover = match ImageReader::open(&cover_image_path) {
            Ok(reader) => match reader.decode() {
                Ok(img) => img,
                Err(e) => {
                    return EncryptionResponse {
                        request_id: request.request_id,
                        status: "error".into(),
                        message: format!("Failed to decode image {}: {}", cover_image_path.display(), e),
                        encrypted_data: None,
                        original_size: request.file_data.len(),
                        encrypted_size: 0,
                    };
                }
            },
            Err(e) => {
                return EncryptionResponse {
                    request_id: request.request_id,
                    status: "error".into(),
                    message: format!("Failed to open image {}: {}", cover_image_path.display(), e),
                    encrypted_data: None,
                    original_size: request.file_data.len(),
                    encrypted_size: 0,
                };
            }
        };
        let (cw, ch) = cover.dimensions();
        let payload_size = serialized.len();
        // your cover capacity heuristic from main()
        let cover_capacity = (cw as f32 * ch as f32) * 0.375f32;

        let cover_final: DynamicImage = if (payload_size as f32) > cover_capacity {
            let scale_factor = ((payload_size as f32 / cover_capacity).sqrt()).ceil();
            let new_w = (cw as f32 * scale_factor) as u32;
            let new_h = (ch as f32 * scale_factor) as u32;
            cover.resize(new_w, new_h, FilterType::Lanczos3)
        } else {
            cover
        };
        let mut cover_buf = Vec::new();
        if let Err(e) = cover_final.write_to(&mut Cursor::new(&mut cover_buf), ImageFormat::Png) {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to encode resized cover image: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }
        let mut tmp_cover = match Builder::new().suffix(".png").tempfile_in(&tmp_dir) {
        Ok(f) => f,
        Err(e) => {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to create tmp cover file: {}", e),
                encrypted_data: None,
                original_size: request.file_data.len(),
                encrypted_size: 0,
            };
        }
        };
        if let Err(e) = tmp_cover.write_all(&cover_buf).and_then(|_| tmp_cover.flush()) {
        return EncryptionResponse {
            request_id: request.request_id,
            status: "error".into(),
            message: format!("Failed to write tmp cover file: {}", e),
            encrypted_data: None,
            original_size: request.file_data.len(),
            encrypted_size: 0,
        };
        }
        let original_size = request.file_data.len();
        let secret_key = b"supersecretkey_supersecretkey_32";
        let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(key);
        
        let mut tmp_output = match Builder::new().suffix(".png").tempfile_in(&tmp_dir) {
        Ok(f) => f,
        Err(e) => {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to create temp output file: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }
        };
        if let Err(e) = hide_prepare()
        .with_file(tmp_payload.path())
        .with_image(tmp_cover.path())
        .with_output(tmp_output.path())
        .using_password(password_hex.as_str())
        .execute()
        {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Steganography failed: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }
        let stego_bytes = match fs::read(tmp_output.path()) {
        Ok(bytes) => bytes,
        Err(e) => {
            return EncryptionResponse {
                request_id: request.request_id,
                status: "error".into(),
                message: format!("Failed to read stego output: {}", e),
                encrypted_data: None,
                original_size,
                encrypted_size: 0,
            };
        }
        };
        println!(
        "[Server] [Req #{}] Stego encryption complete: {} bytes → {} bytes",
        request.request_id,
        original_size,
        stego_bytes.len()
        );

        EncryptionResponse {
        request_id: request.request_id,
        status: "success".into(),
        message: format!(
            "Stego image successfully generated ({} bytes)",
            stego_bytes.len()
        ),
        encrypted_data: Some(stego_bytes.clone()),
        original_size,
        encrypted_size: stego_bytes.len(),
        }
    }

    fn main() -> Result<(), Box<dyn Error>> {
    // 1️⃣ Load a sample image
    let path = env::current_dir()?;
    println!("Current directory: {}", path.display());
    let test_image_path = "../resources/input.jpg";
    println!("Loading input image");
    let image_bytes = fs::read(test_image_path)?;
    println!("Loaded input image: {} ({} bytes)", test_image_path, image_bytes.len());

    // 2️⃣ Build request
    let req = EncryptionRequest {
        request_id: 101,
        filename: "input.png".to_string(),
        file_data: image_bytes,
    };

    // 3️⃣ Call encryption
    let res: EncryptionResponse = encrypt_data(req);

    // 4️⃣ Validate response
    assert_eq!(res.status, "success", "Encryption did not return success");

    println!("\n--- Encryption Response ---");
    println!("Request ID: {}", res.request_id);
    println!("Status: {}", res.status);
    println!("Message: {}", res.message);
    println!("Original Size: {} bytes", res.original_size);
    println!("Encrypted Size: {} bytes", res.encrypted_size);

    // 5️⃣ Save embedded image to check manually
    if let Some(stego_bytes) = res.encrypted_data {
        println!("Stego size before save: {}", stego_bytes.len());
        let tmp_path = PathBuf::from("/tmp/test_stego_output.png");
        fs::write(&tmp_path, &stego_bytes)?;
        let tmp_path2 = PathBuf::from("server_storage/extracted_payloads.png");
        fs::write(&tmp_path2, &stego_bytes)?;
        let read_back = fs::read(&tmp_path2)?;
        println!("Stego size after save: {}", read_back.len());
        println!("✅ Stego image written to {}", tmp_path.display());

        let tmp_extract_dir = tempfile::tempdir_in("/tmp")?;
        println!("Temporary extraction folder: {}", tmp_extract_dir.path().display());

        //let output_dir = PathBuf::from("./extracted_payloads");
        //fs::create_dir_all(&output_dir)?; // create if not exists
        //println!("Extraction folder: {}", output_dir.display());

        let secret_key = b"supersecretkey_supersecretkey_32";
        let key = Key::<Aes256Gcm>::from_slice(secret_key);
        let password_hex = hex::encode(key);
        extract_prepare()
        .using_password(password_hex.as_str())
        .from_secret_file(&tmp_path)
        .into_output_folder(tmp_extract_dir.path())
        //.into_output_folder(&output_dir)
        .execute()
        .expect("Failed to unveil message from image");
        println!("Extracted payload to {}", tmp_extract_dir.path().display());
        //println!("Extracted payload to {}", &output_dir.display());

    // 3️⃣ Find the extracted payload file
    let extracted_file_path = fs::read_dir(tmp_extract_dir.path())?
    //let extracted_file_path = fs::read_dir(&output_dir)?
        .next()
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No extracted file found",
        ))??
        .path();
        println!("Found extracted file: {}", extracted_file_path.display());

        // 4️⃣ Read and deserialize payload
        let extracted_bytes = fs::read(&extracted_file_path)?;
        let recovered: HiddenPayload = bincode::deserialize(&extracted_bytes)?;

        println!("\n--- Extracted Payload ---");
        println!("Recovered message: {}", recovered.message);
        println!("Views: {}", recovered.views);
        if let Some(extra) = &recovered.extra {
            println!("Extra: {}", extra);
        }

    } else {
        println!("⚠️ No encrypted data found in response");
    }

    Ok(())
}
