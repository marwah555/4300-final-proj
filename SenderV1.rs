use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpListener;

const BLOCK_SIZE: usize = 16;

fn generate_key(key_bits: usize) -> Result<Vec<u8>> {
    let mut key = vec![0u8; key_bits / 8];
    rand::thread_rng().fill(&mut key[..]);
    let mut file = File::create("aes_key.bin")?;
    file.write_all(&key)?;
    Ok(key)
}

fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut iv = vec![0u8; BLOCK_SIZE];
    rand::thread_rng().fill(&mut iv[..]);

    let cipher = match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        _ => panic!("Unsupported key length"),
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
    let key = generate_key(128)?; // Change to 192 or 256 for other modes
    let listener = TcpListener::bind("0.0.0.0:12364")?;
    println!("[Sender] Listening on port 12364...");

    let (mut stream, _) = listener.accept()?;
    println!("[Sender] Client connected.");

    // Change file name based on benchmark test
    let file_path = "sample_text.txt";
    let mut file = BufReader::new(File::open(file_path)?);
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let encrypted = encrypt_data(&buffer, &key)?;
    stream.write_u32::<BigEndian>(encrypted.len() as u32)?;
    stream.write_all(&encrypted)?;

    println!("[Sender] Sent encrypted file of size: {}", encrypted.len());
    Ok(())
}
