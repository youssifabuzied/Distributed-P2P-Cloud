use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

use image::{RgbaImage};
use rand::Rng;
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Inputs ===
    let input_path = "resources/input.jpg";
    let output_path = "resources/output_stego.png";
    let secret_key = b"supersecretkey_supersecretkey_32"; // 32 bytes for AES-256

    let items = vec![
        "Hidden message one",
        "Another secret text",
        "42",
        "https://example.com"
    ];

    // Combine all items into one string
    let combined = items.join("|SEP|");

    // Encrypt before hiding
    let key = Key::<Aes256Gcm>::from_slice(secret_key);
    println!("Key (hex): {}", hex::encode(key));
    let cipher = Aes256Gcm::new(&key);
    println!("Cipher created.");
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    println!("Original Nonce (hex): {}", hex::encode(&nonce));
    let ciphertext = cipher.encrypt(&nonce, combined.as_ref()).map_err(|e| format!("Encryption failed: {:?}", e))?;
    println!("Plaintext: {:?}",combined);
    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));
    println!("Ciphertext length: {}", ciphertext.len());
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|e| format!("Decryption failed: {:?}", e))?;
    println!("Decrypted text: {:?}", String::from_utf8_lossy(&plaintext));
    //assert_eq!(&plaintext, b"plaintext message");
    // Store nonce + ciphertext as bytes
    let mut data_to_hide = Vec::new();
    let data_len = (nonce.len() + ciphertext.len()) as u32;
    data_to_hide.extend_from_slice(&data_len.to_be_bytes());
    data_to_hide.extend_from_slice(&nonce);
    data_to_hide.extend_from_slice(&ciphertext);
    println!("Total data_to_hide length: {}", data_to_hide.len());
    println!("Data to hide (first 32 bytes hex): {}", hex::encode(&data_to_hide[..32.min(data_to_hide.len())]));
    // let mut data_to_hide = nonce.to_vec();
    // data_to_hide.extend(ciphertext);

    // Encode into image
    let img = image::open(input_path)?.to_rgba8();
    let stego = encode_lsb(&img, &data_to_hide)?;
    stego.save(output_path)?;

    println!("Data encoded and saved as {output_path}");

    // === Decode example ===
    let decoded = decode_lsb(&stego)?;
    let (len_bytes, rest) = decoded.split_at(4);
    let data_len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
    let data = &rest[..data_len];

    
    let (nonce_bytes, cipher_bytes) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    println!("Decoded total length: {}", data.len());
    println!("Nonce (hex): {}", hex::encode(&nonce));
    let plaintext = cipher.decrypt(nonce, cipher_bytes).map_err(|e| format!("Decryption failed: {:?}", e))?;

    let message = String::from_utf8(plaintext)?;
    println!("Decoded messages: {:?}", message.split("|SEP|").collect::<Vec<_>>());

    Ok(())
}

fn encode_lsb(img: &RgbaImage, data: &[u8]) -> Result<RgbaImage, String> {
    let mut out = img.clone();

    // Prefix data length (4 bytes, little endian)
    let mut payload = (data.len() as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(data);

    let total_bits = payload.len() * 8;
    let capacity = out.width() as usize * out.height() as usize * 3; // RGB only

    if total_bits > capacity {
        return Err(format!(
            "Data too large to encode ({} bits > {} bits capacity)",
            total_bits, capacity
        ));
    }

    let mut bit_idx = 0;
    for pixel in out.pixels_mut() {
        for chan in pixel.0.iter_mut().take(3) { // only RGB
            if bit_idx >= total_bits { return Ok(out); }
            let byte_idx = bit_idx / 8;
            let bit_in_byte = 7 - (bit_idx % 8);
            let bit = (payload[byte_idx] >> bit_in_byte) & 1;
            *chan = (*chan & 0xFE) | bit;
            bit_idx += 1;
        }
    }
    Ok(out)
}

/// Decode bytes hidden in an RGBA image
fn decode_lsb(img: &RgbaImage) -> Result<Vec<u8>, String> {
    let mut bits = Vec::with_capacity(img.width() as usize * img.height() as usize * 3);
    for pixel in img.pixels() {
        for &chan in pixel.0.iter().take(3) {
            bits.push(chan & 1);
        }
    }

    // Rebuild bytes
    let mut bytes = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 { break; }
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= bit << (7 - i);
        }
        bytes.push(byte);
    }

    // Extract embedded length (first 4 bytes)
    if bytes.len() < 4 {
        return Err("Corrupted data: no length prefix".into());
    }
    let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;

    if bytes.len() < 4 + len {
        return Err(format!(
            "Corrupted data: expected {} bytes but only got {}",
            len,
            bytes.len() - 4
        ));
    }

    Ok(bytes[4..4 + len].to_vec())
}

