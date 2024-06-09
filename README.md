# Mnemonic-Generate-Save (mgs) CLI

A command-line interface (CLI) application for generating and saving secret mnemonics.

## Installation

To install the Secret Mnemonic CLI, follow these steps:

1. Clone the repository:
```
git clone https://github.com/mgravitt/mgs
```

2. Navigate to the project directory and build the CLI:
```
cd mgs
cargo build --release
```

3. The compiled binary will be available at `target/release/mgs`.

## Usage
### Generate
Generate a new secret mnemonic and save it to a file.
```
./target/release/mgs generate --filename my_mnemonic
```
You will be prompted twice to enter an encryption password and the file will be saved. 

### Inspect
Inspect a secret mnemonic file.
```
./target/release/mgs inspect --filename my_mnemonic
```
You will be prompted to enter the password used to encrypt the mnemonic and the mnenonic will be printed to the console. 

## Security

The Secret Mnemonic CLI uses secure encryption techniques to protect the mnemonic:

- The mnemonic is encrypted using AES-256-GCM with a randomly generated nonce.
- The encryption key is derived from the user-provided password using PBKDF2 with HMAC-SHA256 and 100,000 iterations.
- A random 16-byte salt is generated for each encryption operation to protect against rainbow table attacks.

It is crucial to use a strong and unique password to ensure the security of the encrypted mnemonic.

## Dependencies

The Secret Mnemonic CLI relies on the following dependencies:

- [clap](https://crates.io/crates/clap): A command-line argument parser for Rust.
- [ring](https://crates.io/crates/ring): A cryptographic library for Rust.
- [bip39](https://crates.io/crates/bip39): A Rust implementation of the BIP39 standard for mnemonic phrases.
- [rpassword](https://crates.io/crates/rpassword): A Rust library for reading passwords from the terminal.

## License

This project is licensed under the [MIT License](LICENSE).