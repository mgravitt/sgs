# Mnemonic-Generate-Save (mgs) CLI

A command-line interface for generating and saving secret mnemonics.

## Installation

To install the CLI, follow these steps:

Clone the repository:
```
git clone https://github.com/mgravitt/mgs
cd mgs
cargo build --release
```
The compiled binary will be available at `target/release/mgs`.

## Usage
### Generate
Generate a new secret mnemonic and save it to a file.
```
./target/release/mgs generate --filename mnemonic.enc
```
You will be prompted twice to enter an encryption password and the file will be saved. 

### Inspect
Inspect a secret mnemonic file.
```
./target/release/mgs inspect --filename mnemonic.enc
```
You will be prompted to enter the password used to encrypt the mnemonic and the mnenonic will be printed to the console. 

### Optional Arguments
#### Password
The password is used to encrypt the mnemonic. It can be passed as an environment variable or as a command line argument.
```
PASSWORD=my_password ./target/release/mgs generate --filename mnemonic.enc
```
or
```
./target/release/mgs generate --password my_password --filename mnemonic.enc
```
#### Word Count
The number of words in the mnemonic phrase. The default is 12. 
```
./target/release/mgs generate --word-count 24 --filename mnemonic.enc
```

#### Filename
The filename is the name of the file that the mnemonic will be saved to.

## Security

The CLI uses secure encryption techniques to protect the mnemonic:

- The mnemonic is encrypted using AES-256-GCM with a randomly generated nonce.
- The encryption key is derived from the user-provided password using PBKDF2 with HMAC-SHA256 and 262_144 iterations.
- A random 16-byte salt is generated for each encryption operation to protect against rainbow table attacks.

## Example Walkthrough
```sh
> PASSWORD=1234 ./target/release/mgs generate --filename m1.enc
Mnemonic generated and saved successfully to m1.enc.
> PASSWORD=1234 ./target/release/mgs inspect --filename m1.enc
Decrypted mnemonic: trial soda broccoli wear plunge angle afford armed able good symptom mountain
```

## Dependencies

The Secret Mnemonic CLI relies on the following dependencies:

- [clap](https://crates.io/crates/clap): A command-line argument parser for Rust.
- [ring](https://crates.io/crates/ring): A cryptographic library for Rust.
- [bip39](https://crates.io/crates/bip39): A Rust implementation of the BIP39 standard for mnemonic phrases.
- [rpassword](https://crates.io/crates/rpassword): A Rust library for reading passwords from the terminal.

## License

This project is licensed under the [MIT License](LICENSE).