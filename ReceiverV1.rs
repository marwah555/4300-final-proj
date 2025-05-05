use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

const BLOCK_SIZE: usize = 16;

fn decrypt_data(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = &encrypted[..BLOCK_SIZE];

    let cipher = match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        _ => panic!("Unsupported key length"),
    };

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    let mut decrypted = vec![0u8; encrypted.len()];
    let count = crypter.update(&encrypted[BLOCK_SIZE..], &mut decrypted)?;
    let rest = crypter.finalize(&mut decrypted[count..])?;
    decrypted.truncate(count + rest);

    let padding_len = *decrypted.last().unwrap_or(&0) as usize;
    if padding_len > 0 && padding_len <= BLOCK_SIZE {
        decrypted.truncate(decrypted.len() - padding_len);
    }

    Ok(decrypted)
}

fn main() -> Result<()> {
    let mut key_file = File::open("aes_key.bin")?;
    let mut key = Vec::new();
    key_file.read_to_end(&mut key)?;

    let mut stream = TcpStream::connect(("172.20.10.2", 12364))?;
    println!("[Receiver] Connected to sender.");

    let length = stream.read_u32::<BigEndian>()? as usize;
    let mut encrypted = vec![0u8; length];
    stream.read_exact(&mut encrypted)?;

    let decrypted = decrypt_data(&encrypted, &key)?;
    println!("[Receiver] Received and decrypted file. Size: {}", decrypted.len());

    let mut out = File::create("decrypted_output.txt")?;
    out.write_all(&decrypted)?;

    Ok(())
}
