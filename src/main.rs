use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use clap::Parser;
use loading::{Loading, Spinner};
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::process::exit;
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
    let loader = Loading::new(Spinner::new(vec!["↱", "↲"]));

    loader.text("Starting...");

    loader.text("Reading File Content");

    let file_content = match read(path_file) {
        Ok(content) => content,
        Err(err) => {
            loader.fail(err);
            exit(0)
        }
    };

    if path_file.extension().unwrap() == "fox" {
        let key = arg.key.unwrap();

        loader.text("Key flag supplied... Decrypting...");

        if key.is_empty() {
            loader.fail("You must provide a key to decrypt the file.");

            return Ok(());
        }

        let cipher_key = Key::from_slice(&key.as_bytes());
        let nonce = Nonce::from_slice(NONCE);
        let cipher = Aes256Gcm::new(cipher_key);

        let decrypted_content = match cipher.decrypt(nonce, file_content.as_ref()) {
            Ok(content) => content,
            Err(why) => {
                loader.fail(why);
                exit(0)
            }
        };

        match write(
            format!("{}", path_file.file_stem().unwrap().to_str().unwrap()),
            decrypted_content,
        ) {
            Err(why) => {
                loader.fail(why);
                exit(0)
            }
            Ok(out) => out,
        };

        loader.success("Successfully decrypted");

        return Ok(());
    }

    loader.text("Encrypting file...");

    let mut rnd = rand::thread_rng();
    let rnd_key: String = (0..32).map(|_| rnd.sample(Alphanumeric) as char).collect();
    let cipher_key = Key::from_slice(&rnd_key.as_bytes());
    let nonce = Nonce::from_slice(NONCE);
    let cipher = Aes256Gcm::new(cipher_key);

    let encrypted_content = match cipher.encrypt(nonce, file_content.as_ref()) {
        Ok(content) => content,
        Err(why) => {
            loader.fail(why);
            exit(0)
        }
    };

    match write(
        format!("{}.fox", path_file.file_name().unwrap().to_str().unwrap()),
        encrypted_content,
    ) {
        Err(why) => {
            loader.fail(why);
            exit(0)
        }
        Ok(out) => out,
    };

    let message = format!("Decryption Key: {}", rnd_key);

    loader.success(message);

    Ok(())
}
