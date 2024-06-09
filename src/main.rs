use bip39::{Language, Mnemonic, MnemonicType};
use clap::{Parser, Subcommand, ValueEnum};
use secp256k1::{rand::rngs::OsRng, SecretKey};
use std::path::PathBuf;

mod crypto;
use crypto::{read_encrypted_file, write_encrypted_file};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Password to encrypt the mnemonic with
    #[arg(short, long, env = "PASSWORD")]
    password: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new secret mnemonic and save it to a file
    Generate {
        #[command(flatten)]
        args: Args,

        /// Number of words in the mnemonic, 12 or 24
        #[arg(short, long, default_value = "12")]
        word_count: WordCount,

        /// Type of key to generate: "mnemonic" or "private-key"
        #[arg(short, long, env = "KEY_TYPE", default_value = "mnemonic")]
        key_type: KeyType,

        /// Overwrite the file if it already exists
        #[arg(short, long, env = "OVERWRITE", default_value_t = false)]
        overwrite: bool,
    },
    /// Inspect a secret mnemonic from a file
    Inspect {
        #[command(flatten)]
        args: Args,
    },
}

#[derive(Parser)]
struct Args {
    /// File path to save the encrypted mnemonic or read the encrypted mnemonic from
    #[arg(short, long)]
    filename: PathBuf,
}

#[derive(ValueEnum, Clone, Debug)]
enum WordCount {
    #[value(name = "12")]
    Twelve = 12,
    #[value(name = "24")]
    TwentyFour = 24,
}

#[derive(ValueEnum, Clone, Debug)]
enum KeyType {
    #[value(name = "mnemonic")]
    Mnemonic,
    #[value(name = "private-key")]
    PrivateKey,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate {
            args,
            word_count,
            key_type,
            overwrite,
        } => {
            let phrase = match key_type {
                KeyType::Mnemonic => {
                    let mnemonic_type = match word_count {
                        WordCount::Twelve => MnemonicType::Words12,
                        WordCount::TwentyFour => MnemonicType::Words24,
                    };
                    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
                    mnemonic.to_string()
                }
                KeyType::PrivateKey => {
                    let secret_key = SecretKey::new(&mut OsRng);
                    let secret_key_hex = format!("{}", secret_key.display_secret());
                    secret_key_hex
                }
            };

            let password = match &cli.password {
                Some(p) => p.clone(),
                None => {
                    let password = rpassword::prompt_password("Enter password: ").unwrap();
                    let confirm_password =
                        rpassword::prompt_password("Confirm password: ").unwrap();

                    if password != confirm_password {
                        eprintln!("Passwords do not match.");
                        return;
                    }
                    password
                }
            };

            match write_encrypted_file(&args.filename, &phrase, &password, *overwrite) {
                Ok(_) => {
                    println!(
                        "Secret generated and saved successfully to {}.",
                        args.filename.display()
                    );
                }
                Err(e) => {
                    eprintln!("Failed to write encrypted file: {}", e);
                    return;
                }
            }
        }
        Commands::Inspect { args } => {
            let password = match &cli.password {
                Some(p) => p.clone(),
                None => rpassword::prompt_password("Enter password: ").unwrap(),
            };

            let decrypted_secret = read_encrypted_file(&args.filename, &password);

            println!(
                "Decrypted secret: {}",
                String::from_utf8_lossy(&decrypted_secret)
            );
        }
    }
}
