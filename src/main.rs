use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use clap::Parser;
use hex::encode;
use loading::Loading;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha256};
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
    file: String,
    #[clap(short, long)]
    hash: bool,
    #[clap(short, long)]
    key: Option<String>,
    #[clap(short, long)]
    verify: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arg = CLI::parse();
    let file: String = arg.file;
    let path_file = Path::new(&file);
    let loader = Loading::default();

    loader.info("Starting...");

    loader.info("Reading File Content");

    let file_content = match read(path_file) {
        Ok(content) => content,
        Err(_why) => {
            panic!("File does not exist!")
        }
    };

    if path_file.extension().unwrap() == "fox" {
        if let None = arg.key.as_deref() {
            loader.fail("You must provide a key to decrypt the file.");

            return Ok(());
        }

        let key = arg.key.unwrap();

        if let Some(verify_hash) = arg.verify.as_deref() {
            loader.info("Verifying .fox file...");

            let hash_sha = hash_file(path_file, &loader);

            if hash_sha != verify_hash {
                loader.fail("Hashes Do Not Match!");

                return Ok(());
            }

            loader.success("Hashes Match!")
        }

        let cipher_key = Key::from_slice(&key.as_bytes());
        let nonce = Nonce::from_slice(NONCE);
        let cipher = Aes256Gcm::new(cipher_key);

        let decrypted_content = match cipher.decrypt(nonce, file_content.as_ref()) {
            Ok(content) => content,
            Err(_why) => {
                panic!("Could not Decrypt the file!")
            }
        };

        loader.success("Successfully Decrypted");

        match write(
            format!("{}", path_file.file_stem().unwrap().to_str().unwrap()),
            decrypted_content,
        ) {
            Err(_why) => {
                panic!("Could not write the decrypted file!")
            }
            Ok(out) => out,
        };

        loader.success("Written File!");

        loader.end();

        return Ok(());
    }

    loader.info("Encrypting file...");

    let mut rnd = rand::thread_rng();
    let rnd_key: String = (0..32).map(|_| rnd.sample(Alphanumeric) as char).collect();
    let cipher_key = Key::from_slice(&rnd_key.as_bytes());
    let nonce = Nonce::from_slice(NONCE);
    let cipher = Aes256Gcm::new(cipher_key);

    let encrypted_content = match cipher.encrypt(nonce, file_content.as_ref()) {
        Ok(content) => content,
        Err(_why) => {
            panic!("Could not Encrypt the file!")
        }
    };

    loader.success("File Encrypted!");

    match write(
        format!("{}.fox", path_file.file_name().unwrap().to_str().unwrap()),
        encrypted_content,
    ) {
        Err(_why) => {
            panic!("Could not write the Encrypted file!")
        }
        Ok(out) => out,
    };

    loader.success("File Written!");

    if arg.hash {
        let hex_sha = hash_file(path_file, &loader);

        loader.success(format!("Successfully Hashed File! {}", hex_sha));
    }

    let message = format!("Decryption Key: {}", rnd_key);

    loader.success(message);
    loader.end();

    Ok(())
}

fn hash_file(path: &Path, loader: &Loading) -> String {
    loader.info("Computing File Hash...");
    let mut hasher = Sha256::new();

    let content = match read(path) {
        Ok(content) => content,
        Err(_why) => {
          panic!("Something went wrong while hashing the file!")
        }
    };

    loader.success("Computed Hash!");

    hasher.update(content);

    let hash = hasher.finalize().to_vec();
    let hex_sha = encode(hash);

    return hex_sha;
}
