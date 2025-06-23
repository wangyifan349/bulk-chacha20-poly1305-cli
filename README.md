# bulk-chacha20-poly1305-cli

A Rust-based tool for batch **ChaCha20-Poly1305** file **encryption and decryption**, supporting recursive directory processing, secure password derivation, file permission preservation, and a user-friendly terminal interface.

---

## Features

- Uses modern and secure AEAD algorithm **ChaCha20-Poly1305** for both encryption and decryption.
- Batch and recursively processes all files in the specified directory, including subdirectories.
- Passwords are securely derived using **Argon2**, providing high-strength encryption keys.
- Interactive command-line interface with hidden password input and double confirmation for simplicity and security.
- Preserves original file permissions to prevent accidental permission loss (supported on Unix systems).
- Generates a unique random `nonce` for each file to ensure encryption security.
- Robust error handling: single file failures do not interrupt the entire batch process; status indications are displayed.

---

## Requirements

- Rust (recommended version 1.65+)
- Dependencies:
  - `chacha20poly1305` (encryption/decryption)
  - `argon2` (secure password derivation)
  - `walkdir` (directory traversal)
  - `dialoguer` (interactive command line interface)
  - `rand` (random number generation)
  - `anyhow` (simple error handling)

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

- Choose operation mode (Encrypt / Decrypt)
- Enter the target directory (make sure it exists and has read/write permissions)
- Enter your password (hidden input with confirmation)

The program will recursively process all files under the directory and overwrite them with encrypted or decrypted content.

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

- **Security:** Do not use weak passwords. The program currently uses a fixed salt; for production use, it's recommended to modify the code to support dynamic salt generation and storage.
- **Cross-platform:** File permission preservation works only on Unix/Linux/macOS. Windows file permissions work differently, and support will be added in future versions.
- **Backup:** This tool overwrites original files. Always back up important data before encryption to avoid accidental data loss.

---

## Contribution

Contributions through Issues or Pull Requests to improve features or fix bugs are welcome!  
Please follow Rust coding conventions and keep code comments and documentation up to date.

---

## License

MIT License © 2025

---

## Contact

- GitHub: https://github.com/wangyifan349/bulk-chacha20-poly1305-cli  
- Email: wangyifan349@gmail.com

---

Thank you for your interest and support! Wishing you a great experience using this tool. 🎉
