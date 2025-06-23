use anyhow::{bail, Context, Result};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
};
use walkdir::WalkDir;

const NONCE_LEN: usize = 12;
const SALT: &[u8] = b"fixed_salt_for_demo!"; // Example fixed salt, replace for production

/// Reads a trimmed line from standard input.
fn read_line_trim() -> Result<String> {
    let stdin = io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Prompts user to input mode: returns true for encrypt, false for decrypt.
fn prompt_mode() -> Result<bool> {
    loop {
        println!("Please enter operation mode (encrypt/decrypt):");
        let input = read_line_trim()?;

        if input == "encrypt" {
            return Ok(true);
        }

        if input == "decrypt" {
            return Ok(false);
        }

        println!("Invalid input, please type 'encrypt' or 'decrypt'.");
    }
}

/// Prompts user to input a directory path and validates it.
fn prompt_directory() -> Result<String> {
    loop {
        println!("Please enter the directory path to process:");
        let input = read_line_trim()?;
        let path = Path::new(&input);

        if path.is_dir() {
            return Ok(input);
        }

        println!("The path is invalid or not a directory. Please try again.");
    }
}

/// Securely prompts the user to enter a password twice, confirming they match.
fn prompt_password() -> Result<String> {
    loop {
        println!("Please enter password:");
        let password = rpassword::read_password()?;

        if password.is_empty() {
            println!("Password cannot be empty. Please try again.");
            continue;
        }

        println!("Please confirm the password:");
        let confirm = rpassword::read_password()?;

        if password == confirm {
            return Ok(password);
        }

        println!("Passwords do not match. Please try again.");
    }
}

/// Derives a 32-byte key from password and salt using Argon2.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &Params::default(), &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}

/// Encrypts a single file with format: nonce(12 bytes) + ciphertext + tag.
/// Preserves file permissions.
fn encrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    // Read file metadata and permissions
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // Read entire plaintext content
    let mut plaintext = Vec::new();
    File::open(path)?.read_to_end(&mut plaintext)?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt plaintext with nonce
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

    // Overwrite file with nonce + ciphertext
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

    // Restore original permissions
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// Decrypts a single file encrypted with the above format.
/// Preserves file permissions.
fn decrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    // Read file metadata and permissions
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // Read entire file content
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    // Validate length to accommodate nonce and tag
    if data.len() < NONCE_LEN + 16 {
        bail!("File too short to be a valid encrypted file");
    }

    // Split nonce and ciphertext+tag
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt and authenticate ciphertext
    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    // Overwrite file with decrypted plaintext
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&plaintext)?;

    // Restore original permissions
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// Recursively processes all files under the given directory.
/// If encrypt == true, encrypt files; otherwise decrypt files.
fn process_directory(dir_path: &Path, cipher: &ChaCha20Poly1305, encrypt: bool) {
    // Collect all files
    let files: Vec<_> = WalkDir::new(dir_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .collect();

    println!("Found {} files, starting processing...", files.len());

    for (idx, entry) in files.iter().enumerate() {
        let path = entry.path();

        // Call appropriate function based on mode
        let result = if encrypt {
            encrypt_file(path, cipher)
        } else {
            decrypt_file(path, cipher)
        };

        // Print process result
        match result {
            Ok(_) => {
                println!("✅ [{}/{}] Success: {}", idx + 1, files.len(), path.display());
            }
            Err(e) => {
                eprintln!(
                    "❌ [{}/{}] Failed: {} Error: {:?}",
                    idx + 1,
                    files.len(),
                    path.display(),
                    e
                );
            }
        }
    }
}

fn main() -> Result<()> {
    println!("Batch ChaCha20-Poly1305 File Encryption/Decryption Tool");

    // Prompt for mode
    let encrypt = prompt_mode()?;

    // Prompt for directory
    let dir_str = prompt_directory()?;
    let dir_path = Path::new(&dir_str);

    // Prompt for password securely
    let password = prompt_password()?;

    // Derive the encryption key
    let key = derive_key(&password, SALT)?;

    // Initialize the cipher
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    println!(
        "Starting {} of directory: {}",
        if encrypt { "encryption" } else { "decryption" },
        dir_path.display()
    );

    // Process files in directory recursively
    process_directory(dir_path, &cipher, encrypt);

    println!("All files processed. Thank you for using!");
    Ok(())
}
