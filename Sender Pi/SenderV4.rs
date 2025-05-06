use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 24; // 16 = AES-128, 24 = AES-192, 32 = AES-256

fn generate_key() -> Result<Vec<u8>> {
    let mut key = vec![0u8; KEY_SIZE];
    rand::thread_rng().fill(&mut key[..]);
    let mut file = File::create("aes_key.bin")?;
    file.write_all(&key)?;
    println!("[Sender] AES-{} Key: {:02x?}", KEY_SIZE * 8, key);
    Ok(key)
}

fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut iv = vec![0u8; BLOCK_SIZE];
    rand::thread_rng().fill(&mut iv[..]);

    let cipher = match KEY_SIZE {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        _ => panic!("Unsupported key size: {}", KEY_SIZE),
    };

    let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))?;
    let mut ciphertext = vec![0u8; padded.len() + BLOCK_SIZE];
    let count = crypter.update(&padded, &mut ciphertext)?;
    let rest = crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count + rest);

    let mut output = iv;
    output.extend(ciphertext);
    Ok(output)
}

fn main() -> Result<()> {
    let key = std::fs::read("aes_key.bin").unwrap_or_else(|_| {
        generate_key().expect("Failed to generate and save AES key")
    });

    let listener = TcpListener::bind("0.0.0.0:12364")?;
    println!("[Sender] Listening on port 12364...");

    let (mut stream, addr) = listener.accept()?;
    println!("[Sender] Connected to {:?}", addr);

    let mut log_file = OpenOptions::new().create(true).append(true).open("sender_log.txt")?;
    let mut file = File::open("sample_text.txt")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let start = Instant::now();
    let encrypted = encrypt_data(&buffer, &key)?;
    let duration = start.elapsed();

    writeln!(
        log_file,
        "Encrypted {} bytes in {:.3?} ({:.2} KB/s)",
        buffer.len(),
        duration,
        (buffer.len() as f64 / 1024.0) / duration.as_secs_f64()
    )?;

    let mut out_file = File::create("encrypted_output.txt")?;
    out_file.write_all(&encrypted)?;

    stream.write_u32::<BigEndian>(encrypted.len() as u32)?;
    stream.write_all(&encrypted)?;

    // 🔧 NEW: delay to give receiver time to read
    std::thread::sleep(Duration::from_secs(2));

    println!("[Sender] Encrypted data sent and saved to encrypted_output.txt");
    Ok(())
}
