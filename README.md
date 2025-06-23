# bulk-chacha20-poly1305-cli

A Rust-based tool for batch **ChaCha20-Poly1305** file **encryption and decryption**, supporting recursive directory processing, secure password derivation, file permission preservation, and a user-friendly terminal interface.

---

## Features

- Utilizes the modern and secure AEAD algorithm **ChaCha20-Poly1305** for both encryption and decryption.
- Performs batch and recursive processing of all files within the specified directory, including subdirectories.
- Passwords are securely derived using **Argon2**, ensuring high-strength encryption keys.
- Provides an interactive command-line interface with hidden password input and double confirmation for enhanced security and usability.
- Preserves original file permissions to prevent accidental permission loss (currently supported on Unix-like systems).
- Generates a unique random `nonce` for each file to ensure encryption security.
- Implements robust error handling: failure on individual files does not interrupt the entire batch; detailed status indications are provided.

---

## Requirements

- Rust (recommended version 1.65+)
- Dependencies:
  - `chacha20poly1305` (encryption/decryption)
  - `argon2` (secure password derivation)
  - `walkdir` (directory traversal)
  - `dialoguer` (interactive command-line interface)
  - `rand` (random number generation)
  - `anyhow` (error handling)

---

## Quick Start

### Build

```bash
git clone https://github.com/wangyifan349/bulk-chacha20-poly1305-cli.git
cd bulk-chacha20-poly1305-cli
cargo build --release
```

### Run

```bash
./target/release/bulk-chacha20-poly1305-cli
```

Follow the interactive prompts:

- Choose the operation mode (Encrypt / Decrypt)
- Enter the target directory (make sure it exists and has read/write permissions)
- Enter your password (hidden input with confirmation)

The program will recursively process all files in the directory and overwrite them with encrypted or decrypted content.

---

## Usage Example

```text
==================================================
🛡️  Batch ChaCha20-Poly1305 File Encryption/Decryption Tool
==================================================
? Please select the operation mode
  ▸ 🔒 Encrypt
    🔓 Decrypt
? Enter the directory to process: /home/user/secrets
? Enter password: [hidden]
? Confirm password: [hidden]

🚀 Starting to encrypt directory: /home/user/secrets
Found 5 files, starting processing...
✅ [1/5] Encryption successful
✅ [2/5] Encryption successful
❌ [3/5] Failed to process: /home/user/secrets/private.txt, error:…
...
✨ All files processed.
Thank you for using the tool! Goodbye 🤗
```

---

## Notes

- **Security:** Avoid using weak passwords. Currently, the program uses a fixed salt; for production environments, it is recommended to modify the code to support dynamic salt generation and storage.
- **Cross-platform:** File permission preservation is supported only on Unix/Linux/macOS. Windows file permissions behave differently; support may be added in the future.
- **Backup:** This tool overwrites original files. Please back up important data prior to encryption to prevent accidental loss.

---

## Contribution

Contributions via Issues or Pull Requests to improve features or fix bugs are highly welcome!  
Please follow Rust coding conventions and maintain clear comments and documentation.

---

## License

MIT License © 2025

---

## Contact

- GitHub: https://github.com/wangyifan349/bulk-chacha20-poly1305-cli  
- Email: wangyifan349@gmail.com

---

Thank you for your interest and support! Wishing you a great experience using this tool. 🎉
