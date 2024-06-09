# Mnemonic-Generate-Save (sgs) CLI

A command-line interface for generating and saving secret mnemonics.

## Installation

To install the CLI, follow these steps:

Clone the repository:
```
git clone https://github.com/mgravitt/sgs
cd sgs
cargo build --release
```
The compiled binary will be available at `target/release/sgs`.

## Usage
### Generate
Generate a new secret mnemonic and save it to a file.
```
./target/release/sgs generate --filename mnemonic.enc
```
You will be prompted twice to enter an encryption password and the file will be saved. 

### Inspect
Inspect a secret mnemonic file.
```
./target/release/sgs inspect --filename mnemonic.enc
```
You will be prompted to enter the password used to encrypt the mnemonic and the mnenonic will be printed to the console. 

### Optional Arguments
#### Password
The password is used to encrypt the mnemonic. It can be passed as an environment variable or as a command line argument.
```
PASSWORD=my_password ./target/release/sgs generate --filename mnemonic.enc
```
or
```
./target/release/sgs generate --password my_password --filename mnemonic.enc
```
#### Word Count
The number of words in the mnemonic phrase. The default is 12. 
```
./target/release/sgs generate --word-count 24 --filename mnemonic.enc
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
> PASSWORD=1234 ./target/release/sgs generate --filename m1.enc
Mnemonic generated and saved successfully to m1.enc.
> PASSWORD=1234 ./target/release/sgs inspect --filename m1.enc
Decrypted secret: trial soda broccoli wear plunge angle afford armed able good symptom mountain

> PASSWORD=1234 ./target/release/sgs generate --filename pk1.enc --key-type private-key --overwrite
Key generated and saved successfully to pk1.enc.
> PASSWORD=1234 ./target/release/sgs inspect --filename pk1.enc
Decrypted secret: 15cd890528ff2ff94204f5fb4a8437ac4535603b6894c88af908565d863250dd
```

## Dependencies

The Secret Mnemonic CLI relies on the following dependencies:

- [clap](https://crates.io/crates/clap): A command-line argument parser for Rust.
- [ring](https://crates.io/crates/ring): A cryptographic library for Rust.
- [bip39](https://crates.io/crates/bip39): A Rust implementation of the BIP39 standard for mnemonic phrases.
- [rpassword](https://crates.io/crates/rpassword): A Rust library for reading passwords from the terminal.

## License

This project is licensed under the [MIT License](LICENSE).