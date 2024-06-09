use bip39::{Language, Mnemonic, MnemonicType};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod crypto;
use crypto::{read_encrypted_file, write_encrypted_file};

#[derive(Parser)]
#[command(name = "secret-mnemonic")]
#[command(about = "Generate and save secret mnemonics", long_about = None)]
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

        /// Overwrite the file if it already exists
        #[arg(short, long, default_value_t = false)]
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

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate {
            args,
            word_count,
            overwrite,
        } => {
            let mnemonic_type = match word_count {
                WordCount::Twelve => MnemonicType::Words12,
                WordCount::TwentyFour => MnemonicType::Words24,
            };

            let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
            let phrase = mnemonic.to_string();

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

            write_encrypted_file(&args.filename, &phrase, &password, *overwrite);

            println!(
                "Mnemonic generated and saved successfully to {}.",
                args.filename.display()
            );
        }
        Commands::Inspect { args } => {
            let password = match &cli.password {
                Some(p) => p.clone(),
                None => rpassword::prompt_password("Enter password: ").unwrap(),
            };

            let decrypted_mnemonic = read_encrypted_file(&args.filename, &password);

            println!(
                "Decrypted mnemonic: {}",
                String::from_utf8_lossy(&decrypted_mnemonic)
            );
        }
    }
}
