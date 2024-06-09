use ring::rand::SecureRandom;
use ring::{
    aead::{self, Aad, BoundKey, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN},
    pbkdf2, rand,
};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

pub const SALT_LENGTH: usize = 16;

/// Reads an encrypted file and returns the decrypted data.
///
/// # Arguments
///
/// * `filename` - The path to the encrypted file.
/// * `password` - The password used for decryption.
///
/// # Returns
///
/// The decrypted data as a vector of bytes.
pub fn read_encrypted_file<P: AsRef<Path>>(filename: P, password: &str) -> Vec<u8> {
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce = [0u8; NONCE_LEN];
    let mut encrypted_data = Vec::new();

    let mut file = File::open(filename).expect("Failed to open file");
    file.read_exact(&mut salt)
        .expect("Failed to read salt from file");
    file.read_exact(&mut nonce)
        .expect("Failed to read nonce from file");
    file.read_to_end(&mut encrypted_data)
        .expect("Failed to read encrypted data from file");
    decrypt(encrypted_data, &salt, &nonce, password)
}

/// Encrypts the given phrase and writes the encrypted data to a file.
///
/// # Arguments
///
/// * `filename` - The path to the output file.
/// * `phrase` - The phrase to encrypt.
/// * `password` - The password used for encryption.
/// * `overwrite` - Whether to overwrite the file if it already exists.
pub fn write_encrypted_file<P: AsRef<Path>>(
    filename: P,
    phrase: &str,
    password: &str,
    overwrite: bool,
) -> Result<(), io::Error> {
    let path = filename.as_ref();
    if path.exists() && !overwrite {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "File already exists and overwrite is set to false",
        ));
    }

    let phrase_bytes = phrase.as_bytes().to_vec();
    let (encrypted_data, salt, nonce) = encrypt(phrase_bytes, password);

    let mut file = File::create(path)?;
    file.write_all(&salt)?;
    file.write_all(&nonce)?;
    file.write_all(&encrypted_data)?;

    Ok(())
}

/// Encrypts the given data using the provided password.
///
/// # Arguments
///
/// * `data` - The data to encrypt.
/// * `password` - The password used for encryption.
///
/// # Returns
///
/// A tuple containing the encrypted data, salt, and nonce.
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
        std::num::NonZeroU32::new(262_144).unwrap(), // same iterations as Geth
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

/// Decrypts the given encrypted data using the provided salt, nonce, and password.
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted data to decrypt.
/// * `salt` - The salt used for key derivation.
/// * `nonce` - The nonce used for encryption.
/// * `password` - The password used for decryption.
///
/// # Returns
///
/// The decrypted data as a vector of bytes.
fn decrypt(encrypted_data: Vec<u8>, salt: &[u8], nonce: &[u8], password: &str) -> Vec<u8> {
    let mut key = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(262_144).unwrap(), // same iterations as Geth
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, world!".to_vec();
        let password = "password123";

        let (encrypted_data, salt, nonce) = encrypt(data.clone(), password);
        let decrypted_data = decrypt(encrypted_data, &salt, &nonce, password);

        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn test_write_read_encrypted_file() {
        let phrase = "This is a secret phrase.";
        let password = "password123";

        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let file_path = temp_file.path();

        write_encrypted_file(file_path, phrase, password, true)
            .expect("Failed to write encrypted file");
        let decrypted_phrase = read_encrypted_file(file_path, password);

        assert_eq!(phrase.as_bytes(), decrypted_phrase.as_slice());

        fs::remove_file(file_path).expect("Failed to remove temporary file");
    }

    #[test]
    fn test_no_overwrite_existing_file() {
        let initial_phrase = "Initial phrase.";
        let new_phrase = "New secret phrase.";
        let password = "password123";

        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let file_path = temp_file.path();

        // Write the initial phrase to the file
        write_encrypted_file(file_path, initial_phrase, password, true)
            .expect("Failed to write initial encrypted file");

        // Attempt to write a new phrase without overwriting
        let result = write_encrypted_file(file_path, new_phrase, password, false);

        // Ensure the function returned an error
        assert!(result.is_err(), "File should not be overwritten");

        // Ensure the content has not changed
        let decrypted_phrase = read_encrypted_file(file_path, password);
        assert_eq!(initial_phrase.as_bytes(), decrypted_phrase.as_slice());

        fs::remove_file(file_path).expect("Failed to remove temporary file");
    }
}
