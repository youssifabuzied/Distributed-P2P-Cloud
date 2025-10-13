
use image::{io::Reader as ImageReader, imageops::FilterType, DynamicImage,GenericImageView,load_from_memory};
use std::fs;
use image::ImageFormat;
use std::env;
use show_image::{create_window,ImageView, ImageInfo,run_context, event};
use hex;
use std::fs::File;
use aes_gcm::{Aes256Gcm, Key};
//use aes_gcm::aead::{Aead, OsRng};
use std::io::Write;
use serde::{Serialize, Deserialize};
use bincode;
use std::io::Cursor;
use anyhow::Result;
use stegano_core::api::hide::prepare as hide_prepare;
use stegano_core::api::unveil::prepare as extract_prepare;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tempfile::Builder;

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
    println!("Serialized payload: {} bytes", serialized.len());

    let tmp_dir = PathBuf::from("/tmp/");
    fs::create_dir_all(&tmp_dir)?; // ensure temp folder exists

    let mut tmp_payload = tempfile::NamedTempFile::new_in(&tmp_dir)?;
    tmp_payload.write_all(&serialized)?;
    tmp_payload.flush()?;
    println!("Temporary payload file: {}", tmp_payload.path().display());

    let cover = ImageReader::open(cover_image_path)?.decode()?;
    let (cw, ch) = cover.dimensions();
    let payload_size = serialized.len();
    let cover_capacity = (cw * ch) as f32 * 0.375;

    let cover_final: DynamicImage = if payload_size as f32 > cover_capacity {
        let scale_factor = ((payload_size as f32 / cover_capacity as f32).sqrt()).ceil();
        let new_w = (cw as f32 * scale_factor) as u32;
        let new_h = (ch as f32 * scale_factor) as u32;
        println!(
            "Resizing cover image in-memory: {}x{} → {}x{} (to fit {} bytes)",
            cw, ch, new_w, new_h, payload_size
        );
        cover.resize(new_w, new_h, FilterType::Lanczos3)
    } else {
        cover
    };

    // Convert resized cover image to PNG bytes (in-memory)
    let mut cover_buf = Vec::new();
    cover_final.write_to(&mut Cursor::new(&mut cover_buf), ImageFormat::Png)?;
    
    let mut tmp_cover = Builder::new()
    .suffix(".png")
    .tempfile_in(&tmp_dir)?;

    //cover_final.write_to(&mut std::io::Cursor::new(&mut cover_buf), ImageFormat::Png)?;
    tmp_cover.write_all(&cover_buf)?;
    tmp_cover.flush()?;
    println!("Temporary resized cover file: {}", tmp_cover.path().display());

    // Build cipher
    let key = Key::<Aes256Gcm>::from_slice(secret_key);
    let password_hex = hex::encode(key);
    println!("Password (derived hex): {}", password_hex);

    hide_prepare()
        .with_file(tmp_payload.path())    // the serialized payload file
        .with_image(tmp_cover.path())               // carrier image
        .with_output(output_path)                   // output stego image
        .using_password(password_hex.as_str())            // optional password encryption
        .execute()
        .expect("Failed to hide file in image");                                // execute hiding
    println!("Stego image written to {}", output_path);

    let tmp_extract_dir = tempfile::tempdir_in("/tmp")?;
    println!("Temporary extraction folder: {}", tmp_extract_dir.path().display());
    extract_prepare()
        .using_password(password_hex.as_str())
        .from_secret_file(output_path)
        .into_output_folder(tmp_extract_dir.path())
        .execute()
        .expect("Failed to unveil message from image");
    println!("Extracted payload to {}", tmp_extract_dir.path().display());

    let extracted_file_path = fs::read_dir(tmp_extract_dir.path())?
    .next()
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No extracted file found"))??
    .path();
    println!("Found extracted file: {}", extracted_file_path.display());

    // Read extracted payload
    let extracted_bytes = fs::read(&extracted_file_path)?;
    let recovered: HiddenPayload = bincode::deserialize(&extracted_bytes)?;
    println!("Recovered message: {}", recovered.message);
    println!("Views: {}", recovered.views);
    if let Some(extra) = &recovered.extra {
        println!("Extra: {}", extra);
    }


    show_image::run_context(move || -> anyhow::Result<()> {
        let hidden_img = load_from_memory(&recovered.image_bytes)?;
        let rgba = hidden_img.to_rgba8();
        let (width, height) = rgba.dimensions();
        let info = ImageInfo::rgba8(width, height);
        let image_view = ImageView::new(info, rgba.as_raw());
        let window = create_window("Recovered Image", Default::default())?;
        window.set_image("hidden", image_view)?;
        // Keep the window open until the user closes it
        for evt in window.event_channel()? {
            if let event::WindowEvent::CloseRequested(_) = evt {
                break;
            }
        }
        Ok(())
    });

    Ok(())
}
