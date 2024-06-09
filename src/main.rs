use clap::{Parser, Subcommand};
use ring::{
    aead::{self, Aad, BoundKey, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN},
    pbkdf2, rand,
};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use bip39::{Language, Mnemonic, MnemonicType};
use ring::rand::SecureRandom;

const SALT_LENGTH: usize = 16;

#[derive(Parser)]
#[command(name = "secret-mnemonic")]
#[command(about = "Generate and manage secret mnemonics", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new secret mnemonic and save it to a file
    Generate {
        /// File path to save the encrypted mnemonic
        #[arg(short, long)]
        filename: PathBuf,
    },
    /// Inspect a secret mnemonic from a file
    Inspect {
        /// File path to read the encrypted mnemonic from
        #[arg(short, long)]
        filename: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate { filename } => {
            let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
            let phrase = mnemonic.to_string();

            let password = rpassword::prompt_password("Enter password: ").unwrap();
            let confirm_password = rpassword::prompt_password("Confirm password: ").unwrap();

            if password != confirm_password {
                eprintln!("Passwords do not match.");
                return;
            }

            let phrase_bytes = phrase.into_bytes();
            let (encrypted_data, salt, nonce) = encrypt(phrase_bytes, &password);

            let mut file = File::create(filename).expect("Failed to create file");
            file.write_all(&salt).expect("Failed to write salt to file");
            file.write_all(&nonce).expect("Failed to write nonce to file");
            file.write_all(&encrypted_data)
                .expect("Failed to write encrypted data to file");

            println!("Mnemonic generated and saved successfully.");
        }
        Commands::Inspect { filename } => {
            let mut file = File::open(filename).expect("Failed to open file");
            let mut salt = [0u8; SALT_LENGTH];
            let mut nonce = [0u8; NONCE_LEN];
            let mut encrypted_data = Vec::new();

            file.read_exact(&mut salt)
                .expect("Failed to read salt from file");
            file.read_exact(&mut nonce)
                .expect("Failed to read nonce from file");
            file.read_to_end(&mut encrypted_data)
                .expect("Failed to read encrypted data from file");

            let password = rpassword::prompt_password("Enter password: ").unwrap();

            let decrypted_mnemonic = decrypt(encrypted_data, &salt, &nonce, &password);

            println!("Decrypted mnemonic: {}", String::from_utf8_lossy(&decrypted_mnemonic));
        }
    }
}

fn encrypt(data: Vec<u8>, password: &str) -> (Vec<u8>, [u8; SALT_LENGTH], [u8; NONCE_LEN]) {
    let mut salt = [0u8; SALT_LENGTH];
    rand::SystemRandom::new()
        .fill(&mut salt)
        .expect("Failed to generate salt");

    let mut nonce = [0u8; NONCE_LEN];
    rand::SystemRandom::new()
        .fill(&mut nonce)
        .expect("Failed to generate nonce");

    let mut key = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );

    let key = UnboundKey::new(&aead::AES_256_GCM, &key).expect("Failed to create encryption key");
    let mut sealing_key = SealingKey::new(key, Nonce::new(&nonce));

    let mut in_out = data.clone();
    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .expect("Failed to encrypt data");

    (in_out, salt, nonce)
}

fn decrypt(encrypted_data: Vec<u8>, salt: &[u8], nonce: &[u8], password: &str) -> Vec<u8> {
    let mut key = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        salt,
        password.as_bytes(),
        &mut key,
    );

    let key = UnboundKey::new(&aead::AES_256_GCM, &key).expect("Failed to create decryption key");
    let nonce_array = nonce.try_into().expect("Nonce has incorrect length");
    let mut opening_key = OpeningKey::new(key, Nonce::new(&nonce_array));

    let mut in_out = encrypted_data;
    let decrypted_data = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .expect("Failed to decrypt data");

    decrypted_data.to_vec()
}

struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    pub fn new(nonce: &[u8; NONCE_LEN]) -> Self {
        Nonce(*nonce)
    }
}

impl NonceSequence for Nonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        Ok(aead::Nonce::assume_unique_for_key(self.0))
    }
}