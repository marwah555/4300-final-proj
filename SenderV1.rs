use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Instant;

const BLOCK_SIZE: usize = 16;

fn generate_key() -> Result<Vec<u8>> {
    let mut key = vec![0u8; BLOCK_SIZE];
    rand::thread_rng().fill(&mut key[..]);
    let mut file = File::create("aes_key.bin")?;
    file.write_all(&key)?;
    Ok(key)
}

fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut iv = vec![0u8; BLOCK_SIZE];
    rand::thread_rng().fill(&mut iv[..]);

    let cipher = Cipher::aes_128_cbc(); // AES-128
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

fn read_ram_usage_kb() -> u32 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().unwrap_or(0);
                }
            }
        }
    }
    0
}

fn handle_connection(mut stream: TcpStream, key: &[u8]) -> Result<()> {
    let mut log_file = OpenOptions::new().create(true).append(true).open("sender_log.txt")?;

    let pid = std::process::id().to_string();
    let _perf = Command::new("perf")
        .args([
            "stat",
            "-e",
            "instructions,cycles,cache-misses,branches,branch-misses,cpu-clock,task-clock",
            "-p",
            &pid,
            "sleep",
            "10",
        ])
        .stdout(File::create("sender_perf.txt")?)
        .spawn()?;

    // Read test file
    let mut file = File::open("sample_text.txt")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    loop {
        let start = Instant::now();
        let encrypted = encrypt_data(&buffer, key)?;
        let duration = start.elapsed();
        let ram_kb = read_ram_usage_kb();

        writeln!(
            log_file,
            "Encrypted {} bytes in {:.3?} ({:.2} KB/s), RAM: {} KB",
            buffer.len(),
            duration,
            (buffer.len() as f64 / 1024.0) / duration.as_secs_f64(),
            ram_kb
        )?;

        stream.write_u32::<BigEndian>(encrypted.len() as u32)?;
        stream.write_all(&encrypted)?;
    }
}

fn main() -> Result<()> {
    let key = generate_key()?;
    let listener = TcpListener::bind("0.0.0.0:12364")?;
    println!("[Sender] Listening on port 12364...");

    let (stream, addr) = listener.accept()?;
    println!("[Sender] Connected to {:?}", addr);

    handle_connection(stream, &key)
}
