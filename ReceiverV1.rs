use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
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

    // Remove padding
    let padding_len = *decrypted.last().unwrap_or(&0) as usize;
    if padding_len > 0 && padding_len <= BLOCK_SIZE {
        decrypted.truncate(decrypted.len() - padding_len);
    }

    Ok(decrypted)
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

fn main() -> Result<()> {
    let mut key_file = File::open("aes_key.bin")?;
    let mut key = vec![0u8; BLOCK_SIZE];
    key_file.read_exact(&mut key)?;

    let mut log_file = OpenOptions::new().create(true).append(true).open("receiver_log.txt")?;

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
        .stdout(File::create("receiver_perf.txt")?)
        .spawn()?;

    let sender_ip = "172.20.10.2"; // Update if needed
    let mut stream = TcpStream::connect((sender_ip, 12364))?;
    println!("[Receiver] Connected to sender");

    loop {
        let frame_length = stream.read_u32::<BigEndian>()? as usize;
        let mut encrypted_frame = vec![0u8; frame_length];
        stream.read_exact(&mut encrypted_frame)?;

        let start = Instant::now();
        let decrypted = decrypt_data(&encrypted_frame, &key)?;
        let duration = start.elapsed();
        let ram_kb = read_ram_usage_kb();

        writeln!(
            log_file,
            "Decrypted {} bytes in {:.3?} ({:.2} KB/s), RAM: {} KB",
            decrypted.len(),
            duration,
            (decrypted.len() as f64 / 1024.0) / duration.as_secs_f64(),
            ram_kb
        )?;

        // Optional: Save output
        let mut file = File::create("decrypted_output.txt")?;
        file.write_all(&decrypted)?;
    }
}
