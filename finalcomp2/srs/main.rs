use aes::{Aes128, Aes192, Aes256};
use block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use rand::{rngs::OsRng, RngCore};
use std::{fs, time::Instant};
use std::convert::TryInto;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn main() {
    let key_size = 32; // Set to 16, 24, or 32 for AES-128, AES-192, or AES-256

    let input_text = fs::read_to_string("message.txt").expect("Failed to read message.txt");
    let data = input_text.trim_end().as_bytes();

    println!("================ SOFTWARE-ONLY AES ====================");
    //println!("Plaintext: {}\n", input_text.trim_end());

    let mut key = vec![0u8; key_size];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);

    let pad_len = 16 - (data.len() % 16);
    let mut buffer = Vec::from(data);
    buffer.resize(data.len() + pad_len, 0u8);

    let start = Instant::now();

    let (ciphertext, decrypted_data) = match key_size {
        16 => {
            let key: &[u8; 16] = key.as_slice().try_into().unwrap();
            let enc = cbc::Encryptor::<Aes128>::new(key.into(), &iv.into());
            let dec = cbc::Decryptor::<Aes128>::new(key.into(), &iv.into());
            let ct = enc.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len()).unwrap().to_vec();
            let mut dbuf = ct.clone();
            let pt = dec.decrypt_padded_mut::<Pkcs7>(&mut dbuf).unwrap().to_vec();
            (ct, pt)
        }
        24 => {
            let key: &[u8; 24] = key.as_slice().try_into().unwrap();
            let enc = cbc::Encryptor::<Aes192>::new(key.into(), &iv.into());
            let dec = cbc::Decryptor::<Aes192>::new(key.into(), &iv.into());
            let ct = enc.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len()).unwrap().to_vec();
            let mut dbuf = ct.clone();
            let pt = dec.decrypt_padded_mut::<Pkcs7>(&mut dbuf).unwrap().to_vec();
            (ct, pt)
        }
        32 => {
            let key: &[u8; 32] = key.as_slice().try_into().unwrap();
            let enc = cbc::Encryptor::<Aes256>::new(key.into(), &iv.into());
            let dec = cbc::Decryptor::<Aes256>::new(key.into(), &iv.into());
            let ct = enc.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len()).unwrap().to_vec();
            let mut dbuf = ct.clone();
            let pt = dec.decrypt_padded_mut::<Pkcs7>(&mut dbuf).unwrap().to_vec();
            (ct, pt)
        }
        _ => panic!("Invalid key size. Must be 16, 24, or 32."),
    };

    let duration = start.elapsed().as_secs_f64();

    println!("AES Key: {}\n", to_hex(&key));
    println!("AES IV: {}\n", to_hex(&iv));
    //println!("Encrypted (hex): {}\n", to_hex(&ciphertext));
    //println!("Decrypted: {}\n", String::from_utf8_lossy(&decrypted_data));
    println!("Execution Time: {:.6} seconds", duration);

    let blocks = (data.len() as f64 / 16.0).ceil();
    let flops = 4000.0 * blocks;
    let mflops = flops / (duration * 1_000_000.0);
    println!("Approx. MFLOPS: {:.2}", mflops);
}
