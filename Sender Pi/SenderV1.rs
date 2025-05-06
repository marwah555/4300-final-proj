use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::{Duration, Instant};

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

    let cipher = Cipher::aes_128_cbc();
    let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))?;
    let mut ciphertext = vec![0u8; padded.len() + BLOCK_SIZE];
    let count = crypter.update(&padded, &mut ciphertext)?;
    let
