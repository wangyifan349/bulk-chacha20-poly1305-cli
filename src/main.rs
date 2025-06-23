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
const SALT: &[u8] = b"fixed_salt_for_demo!"; // 固定盐示例 / Fixed salt example

/// 读取一行用户输入并去除前后空白
/// Read a line from stdin and trim surrounding whitespace
fn read_line_trim() -> Result<String> {
    let stdin = io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// 交互式选择模式：encrypt 返回 true，decrypt 返回 false
/// Prompt user to input mode, return true for encrypt, false for decrypt
fn prompt_mode() -> Result<bool> {
    loop {
        println!("请输入操作模式 (encrypt/decrypt):"); // Please input operation mode (encrypt/decrypt):
        let input = read_line_trim()?;

        if input == "encrypt" {
            return Ok(true);
        }

        if input == "decrypt" {
            return Ok(false);
        }

        println!("无效输入，只能输入 encrypt 或 decrypt，请重新输入"); // Invalid input, please enter 'encrypt' or 'decrypt'
    }
}

/// 交互式输入目录路径并校验是否有效目录
/// Prompt user to input a directory and verify that it exists
fn prompt_directory() -> Result<String> {
    loop {
        println!("请输入需要处理的目录路径:"); // Please enter the directory path to process:
        let input = read_line_trim()?;
        let path = Path::new(&input);

        if path.is_dir() {
            return Ok(input);
        }

        println!("输入的路径无效或不是目录，请重新输入"); // Invalid path or not a directory, please try again
    }
}

/// 交互式安全读取密码，隐藏输入，要求两次输入相同
/// Prompt user securely for password twice and confirm they match
fn prompt_password() -> Result<String> {
    loop {
        println!("请输入密码:"); // Please enter password:
        let password = rpassword::read_password()?;

        if password.is_empty() {
            println!("密码不能为空，请重新输入"); // Password cannot be empty, try again
            continue;
        }

        println!("请再次输入密码确认:"); // Please re-enter password to confirm:
        let confirm = rpassword::read_password()?;

        if password == confirm {
            return Ok(password);
        }

        println!("两次密码不匹配，请重新输入"); // Passwords do not match, please try again
    }
}

/// 使用 Argon2 从用户密码和盐派生固定长度密钥，返回32字节数组
/// Derive a fixed-length 32-byte key from password and salt using Argon2
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &Params::default(), &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 派生密钥失败: {}", e))?; // Argon2 derive key failed
    Ok(key)
}

/// 对单个文件进行加密，文件格式：nonce(12byte) + 密文 + tag
/// 保留文件原权限
/// Encrypt a single file with format: nonce (12 bytes) + ciphertext + tag
/// Preserve original file permissions
fn encrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    // 读取文件权限 / read file permissions
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // 读取文件所有数据 / read all data from file
    let mut plaintext = Vec::new();
    File::open(path)?.read_to_end(&mut plaintext)?;

    // 生成随机nonce / generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 对数据加密 / encrypt data
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

    // 写回文件：nonce + 密文 / write back nonce + ciphertext into file (overwrite)
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

    // 恢复权限 / restore file permissions
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// 对单个文件解密，格式与加密保持一致
/// 保留文件权限
/// Decrypt a single file (format is nonce + ciphertext + tag)
/// Preserve file permissions
fn decrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    // 读取权限 / read permissions
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // 读取所有文件数据 / read all data
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    // 文件长度判断 / check length: it must at least hold nonce and tag
    if data.len() < NONCE_LEN + 16 {
        bail!("文件长度不足，可能不是有效的加密文件"); // File too short, may be invalid encrypted file
    }

    // 拆分nonce和密文 / split nonce and ciphertext+tag
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 解密并认证 / decrypt and authenticate
    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    // 写回文件覆盖 / write back plaintext overriding original file
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&plaintext)?;

    // 恢复权限 / restore file permissions
    fs::set_permissions(path, permissions)?;

    Ok(())
}

/// 遍历指定目录，递归批量处理所有文件
/// encrypt 为 true 进行加密，false 进行解密
/// Traverse and batch process all files under directory recursively
fn process_directory(dir_path: &Path, cipher: &ChaCha20Poly1305, encrypt: bool) {
    // 收集所有文件 / collect all files
    let files: Vec<_> = WalkDir::new(dir_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .collect();

    println!("找到 {} 个文件，开始处理...", files.len()); // Found {} files to process

    for (idx, entry) in files.iter().enumerate() {
        let path = entry.path();

        // 根据模式调用加密或解密 / call encrypt or decrypt function based on mode
        let result = if encrypt {
            encrypt_file(path, cipher)
        } else {
            decrypt_file(path, cipher)
        };

        // 反馈结果 / report result
        match result {
            Ok(_) => {
                println!("✅ [{}/{}] 成功: {}", idx + 1, files.len(), path.display()); // Success
            }
            Err(e) => {
                eprintln!(
                    "❌ [{}/{}] 失败: {} 错误: {:?}",
                    idx + 1,
                    files.len(),
                    path.display(),
                    e
                ); // Failed with error
            }
        }
    }
}

fn main() -> Result<()> {
    // 欢迎信息 / welcome message
    println!("批量 ChaCha20-Poly1305 文件加密/解密 工具"); // Batch ChaCha20-Poly1305 file encrypt/decrypt tool

    // 交互询问处理模式 / interactive mode prompt
    let encrypt = prompt_mode()?;

    // 交互询问处理目录 / interactive directory prompt
    let dir_str = prompt_directory()?;
    let dir_path = Path::new(&dir_str);

    // 交互安全输入密码 / secure password input prompt
    let password = prompt_password()?;

    // 派生密钥 / derive key
    let key = derive_key(&password, SALT)?;

    // 创建ChaCha20Poly1305 加密器 / create ChaCha20Poly1305 cipher instance
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    println!(
        "开始{}目录: {}",
        if encrypt { "加密" } else { "解密" },
        dir_path.display()
    );

    // 批量处理目录文件 / batch process directory files
    process_directory(dir_path, &cipher, encrypt);

    println!("所有文件处理完成。感谢使用！");
    Ok(())
}
