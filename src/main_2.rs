use anyhow::{anyhow, Context, Result};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use rand::RngCore;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const NONCE_LEN: usize = 12;
const SALT: &[u8] = b"fixed_salt_for_demo!"; // 16 bytes固定盐示例（实际需改进）

/// 交互选择操作模式：加密或解密
fn prompt_mode() -> Result<bool> {
    let choices = &["🔒 加密 (Encrypt)", "🔓 解密 (Decrypt)"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("请选择操作模式")
        .items(choices)
        .default(0)
        .interact()?;

    Ok(selection == 0)
}

/// 交互询问目录路径，验证存在且有效
fn prompt_directory() -> Result<PathBuf> {
    loop {
        let input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("请输入需要处理的目录路径")
            .interact_text()?;

        let path = PathBuf::from(input.trim());
        if path.is_dir() {
            return Ok(path);
        }
        println!("❌ 输入路径不是有效目录，请重新输入！");
    }
}

/// 交互安全输入密码，隐藏输入并二次确认
fn prompt_password() -> Result<String> {
    loop {
        let pwd = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("请输入密码")
            .allow_empty_password(false)
            .interact()?;

        let confirm = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("请再次输入密码以确认")
            .allow_empty_password(false)
            .interact()?;

        if pwd == confirm {
            return Ok(pwd);
        }
        println!("❌ 两次输入密码不匹配，请重新输入！");
    }
}

/// 使用 Argon2 从密码派生 32 字节密钥
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &Params::default(), &mut key)
        .map_err(|e| anyhow!("Argon2 派生密钥失败: {}", e))?;
    Ok(key)
}

/// 加密单个文件，保留权限。格式：[nonce(12)+密文+tag]
fn encrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    let meta = fs::metadata(path)?;
    let perms = meta.permissions();

    let mut plain = Vec::new();
    File::open(path)?.read_to_end(&mut plain)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plain.as_ref())?;

    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(&nonce_bytes)?;
    f.write_all(&ciphertext)?;

    fs::set_permissions(path, perms)?;
    Ok(())
}

/// 解密单个文件，保留权限。格式需符合加密格式
fn decrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    let meta = fs::metadata(path)?;
    let perms = meta.permissions();

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < NONCE_LEN + 16 {
        return Err(anyhow!("文件过短，缺少nonce或tag"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(&plaintext)?;

    fs::set_permissions(path, perms)?;
    Ok(())
}

/// 遍历目录，批量加密或解密所有文件
fn process_directory(dir: &Path, cipher: &ChaCha20Poly1305, encrypt: bool) {
    let files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .collect();

    println!("⚡ 发现 {} 个文件，开始处理...", files.len());

    for (idx, entry) in files.iter().enumerate() {
        let path = entry.path();
        let result = if encrypt {
            encrypt_file(path, cipher)
        } else {
            decrypt_file(path, cipher)
        };

        match result {
            Ok(_) => println!("✅ [{}/{}] 成功: {}", idx + 1, files.len(), path.display()),
            Err(e) => eprintln!("❌ [{}/{}] 失败: {} 错误: {:?}", idx + 1, files.len(), path.display(), e),
        }
    }
}

fn main() -> Result<()> {
    println!("==================================================");
    println!("🛡️  批量 ChaCha20-Poly1305 文件加密/解密工具 v2");
    println!("==================================================");

    let encrypt = prompt_mode()?;
    let dir = prompt_directory()?;
    let password = prompt_password()?;
    println!();

    let key = derive_key(&password, SALT)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    println!(
        "🚀 开始{}目录: {}",
        if encrypt { "加密" } else { "解密" },
        dir.display()
    );

    process_directory(&dir, &cipher, encrypt);

    println!("✨ 所有文件处理完成。感谢使用！再见🤗");
    Ok(())
}
