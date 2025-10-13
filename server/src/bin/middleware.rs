
use image::{RgbaImage, open, load_from_memory};
use std::fs;
use std::env;
use show_image::{create_window,ImageView, ImageInfo};
use hex;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};

use serde::{Serialize, Deserialize};
use bincode;

use stegano_core::api::hide::prepare as hide_prepare;
use stegano_core::api::unveil::prepare as extract_prepare;

#[derive(Serialize, Deserialize, Debug)]
struct HiddenPayload {
    message: String,
    views: i32,
    image_bytes: Vec<u8>, // PNG or JPEG bytes
    extra: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::current_dir()?;
    println!("Current directory: {}", path.display());

    // Paths
    let secret_image_path = "../../resources/input.jpg";   // image to hide
    let cover_image_path = "../../resources/default_image.png"; // visible default image (carrier)
    let output_path = "../../resources/output_stego.png";

    // Key (32 bytes)
    let secret_key = b"supersecretkey_supersecretkey_32";

    // Build payload: message + views + secret image bytes + optional extra
    let payload = HiddenPayload {
        message: "Hidden message one|SEP|Another secret text|SEP|42|SEP|https://example.com".into(),
        views: 42,
        image_bytes: fs::read(secret_image_path)?, // read secret image into bytes
        extra: Some("Metadata info".to_string()),
    };

    // Serialize payload
    let serialized = bincode::serialize(&payload)?;
    fs::write("/tmp/payload.bin", &serialized)?;
    println!("Serialized payload: {} bytes", serialized.len());

    // Build cipher
    let key = Key::<Aes256Gcm>::from_slice(secret_key);
    let password_hex = hex::encode(key);

    hide_prepare()
        .with_file("../../resources/payload.bin")   // the serialized payload file
        .with_image(cover_image_path)               // carrier image
        .with_output(output_path)                   // output stego image
        .using_password(&password_hex)            // optional password encryption
        .execute()
        .expect("Failed to hide file in image");                                // execute hiding
    println!("Stego image written to {}", output_path);

    let temp_extract_path = "/tmp/recovered_payload.bin";
    extract_prepare()
        .using_password(&password_hex)
        .from_secret_file(output_path)
        .into_output_folder(temp_dir.path())
        .execute()
        .expect("Failed to unveil message from image");
    println!("Extracted payload to {}", temp_extract_path);

    // Read extracted payload
    let extracted_bytes = fs::read(temp_extract_path)?;
    let recovered: HiddenPayload = bincode::deserialize(&extracted_bytes)?;
    println!("Recovered message: {}", recovered.message);
    println!("Views: {}", recovered.views);
    if let Some(extra) = &recovered.extra {
        println!("Extra: {}", extra);
    }


      let hidden_img = load_from_memory(&recovered.image_bytes)?;
    let rgba = hidden_img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let info = ImageInfo::rgba8(width, height);
    let image_view = ImageView::new(info, rgba.as_raw());
    let window = create_window("Recovered Image", Default::default())?;
    window.set_image("hidden", image_view)?;

    Ok(())
}
