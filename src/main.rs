use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use clap::Parser;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::{
    error::Error,
    fs::{read, write},
    path::Path,
};

const NONCE: &[u8] = b"Random Nonce";

#[derive(Parser)]
#[clap(name = "Fox ^^")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(author = "Artie")]
#[clap(about = "A simple file Encryption CLI")]
struct CLI {
    #[clap(short, long)]
    key: Option<String>,
    file: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arg = CLI::parse();
    let file: String = arg.file;
    let path_file = Path::new(&file);

    let file_content = read(path_file)?;

    if path_file.extension().unwrap() == "fox" {
        let key = arg.key.unwrap();

        if key.is_empty() {
            println!("You must provide a key to decrypt the file.");

            return Ok(());
        }

        let cipher_key = Key::from_slice(&key.as_bytes());
        let nonce = Nonce::from_slice(NONCE);
        let cipher = Aes256Gcm::new(cipher_key);

        let decrypted_content = cipher
            .decrypt(nonce, file_content.as_ref())
            .expect("Could not decrypt file");

        write(
            format!("{}", path_file.file_stem().unwrap().to_str().unwrap()),
            decrypted_content,
        )?;

        return Ok(());
    }

    let mut rnd = rand::thread_rng();
    let rnd_key: String = (0..32).map(|_| rnd.sample(Alphanumeric) as char).collect();
    let cipher_key = Key::from_slice(&rnd_key.as_bytes());
    let nonce = Nonce::from_slice(NONCE);
    let cipher = Aes256Gcm::new(cipher_key);

    let encrypted_content = cipher
        .encrypt(nonce, file_content.as_ref())
        .expect("Could not encrypt file...");

    write(
        format!("{}.fox", path_file.file_name().unwrap().to_str().unwrap()),
        encrypted_content,
    )?;

    println!("Decryption Key: {}", rnd_key);

    Ok(())
}
