use std::{error::Error, path::Path, fs::{read, write}};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use clap::Parser;

const NONCE: &[u8] = b"Random Nonce";

#[derive(Parser)]
#[clap(name = "Fox ^^")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(author = "Artie")]
#[clap(about = "A simple file Encryption CLI")]
struct CLI {
  #[clap(short, long)]
  key: String,
  file: String
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let arg = CLI::parse();
  let key: String = arg.key;
  let file: String = arg.file;
  let path_file = Path::new(&file);

  if key.is_empty() {
    println!("You must provide a key.");

    return Ok(());
  }

  if key.len() < 32 {
    println!("Your key must be 32 characters long.");

    return Ok(());
  }

  if key.len() > 32 {
    println!("Your key must be 32 characters long.");

    return Ok(());
  }

  let file_content = read(path_file)?;
  let cipher_key = Key::from_slice(&key.as_bytes());
  let nonce = Nonce::from_slice(NONCE);
  let cipher = Aes256Gcm::new(cipher_key);

  if path_file.extension().unwrap() == "fox" {
    let decrypted_content = cipher.decrypt(nonce, file_content.as_ref())
      .expect("Could not decrypt file");

    write(format!("{}", path_file.file_stem().unwrap().to_str().unwrap()), decrypted_content)?;

    return Ok(());
  }

  let encrypted_content = cipher.encrypt(nonce, file_content.as_ref())
    .expect("Could not encrypt file...");

  write(format!("{}.fox", path_file.file_name().unwrap().to_str().unwrap()), encrypted_content)?;
  
  Ok(())
}
