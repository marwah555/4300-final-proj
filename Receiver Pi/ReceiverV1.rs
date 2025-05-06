use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

const BLOCK_SIZE: usize = 16;

fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = &encrypted_data[..BLOCK_SIZE];
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;

    let mut decrypted = vec![0u8; encrypted_data.len()];
    let count = crypter.update(&encrypted_data[BLOCK_SIZE..], &mut decrypted)?;
    let rest = crypter.finalize(&mut decrypted[count..])?;
    decrypted.truncate(count + rest);

    Ok(decrypted)
}

fn main() -> Result<()> {
    let mut key_file = File::open("/home/marwah555/aes_key.bin")?;
    let mut key = vec![0u8; BLOCK_SIZE];
    key_file.read_exact(&mut key)?;
    println!("[Receiver] AES Key: {:02x?}", key);

    let sender_ip = "192.168.1.46"; // Set this to match your sender Pi
    let mut stream = TcpStream::connect((sender_ip, 12364))?;
    println!("[Receiver] Connected to sender");

    let mut log_file = OpenOptions::new().create(true).append(true).open("receiver_log.txt")?;

    loop {
        let frame_length = match stream.read_u32::<BigEndian>() {
            Ok(len) => len as usize,
            Err(e) => {
                eprintln!("Failed to read frame length: {e}");
                break;
            }
        };

        let mut encrypted_frame = vec![0u8; frame_length];
        if let Err(e) = stream.read_exact(&mut encrypted_frame) {
            eprintln!("Failed to read frame: {e}");
            break;
        }

        let start = Instant::now();
        let decrypted = match decrypt_data(&encrypted_frame, &key) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Decryption error: {e}");
                break;
            }
        };
        let duration = start.elapsed();

        writeln!(
            log_file,
            "Decrypted {} bytes in {:.3?} ({:.2} KB/s)",
            decrypted.len(),
            duration,
            (decrypted.len() as f64 / 1024.0) / duration.as_secs_f64()
        )?;

        let mut file = File::create("decrypted_output.txt")?;
        file.write_all(&decrypted)?;
    }

    Ok(())
}
