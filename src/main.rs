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
const SALT: &[u8] = b"fixed_salt_for_demo!"; // 固定盐示例

fn read_line_trim() -> Result<String> {
    let stdin = io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_mode() -> Result<bool> {
    loop {
        println!("请输入操作模式 (encrypt/decrypt):");
        let input = read_line_trim()?;
        match input.as_str() {
            "encrypt" => return Ok(true),
            "decrypt" => return Ok(false),
            _ => println!("无效输入，只能输入 encrypt 或 decrypt，请重新输入"),
        }
    }
}

fn prompt_directory() -> Result<String> {
    loop {
        println!("请输入需要处理的目录路径:");
        let input = read_line_trim()?;
        let path = Path::new(&input);
        if path.is_dir() {
            return Ok(input);
        } else {
            println!("输入的路径无效或不是目录，请重新输入");
        }
    }
}

fn prompt_password() -> Result<String> {
    loop {
        println!("请输入密码:");
        let password = rpassword::read_password()?;
        if password.is_empty() {
            println!("密码不能为空，请重新输入");
            continue;
        }
        println!("请再次输入密码确认:");
        let confirm = rpassword::read_password()?;
        if password == confirm {
            return Ok(password);
        }
        println!("两次密码不匹配，请重新输入");
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &Params::default(), &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 派生密钥失败: {}", e))?;
    Ok(key)
}

fn encrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    let meta = fs::metadata(path)?;
    let perms = meta.permissions();

    let mut plaintext = Vec::new();
    File::open(path)?.read_to_end(&mut plaintext)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(&nonce_bytes)?;
    f.write_all(&ciphertext)?;

    fs::set_permissions(path, perms)?;
    Ok(())
}

fn decrypt_file(path: &Path, cipher: &ChaCha20Poly1305) -> Result<()> {
    let meta = fs::metadata(path)?;
    let perms = meta.permissions();

    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < NONCE_LEN + 16 {
        bail!("文件内容长度不足，无法解密");
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(&plaintext)?;

    fs::set_permissions(path, perms)?;

    Ok(())
}

fn process_directory(dir_path: &Path, cipher: &ChaCha20Poly1305, encrypt: bool) {
    let files: Vec<_> = WalkDir::new(dir_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .collect();

    println!("找到 {} 个文件，开始处理...", files.len());

    for (idx, entry) in files.iter().enumerate() {
        let path = entry.path();
        let res = if encrypt {
            encrypt_file(path, cipher)
        } else {
            decrypt_file(path, cipher)
        };
        match res {
            Ok(_) => println!("✅ [{}/{}] 成功: {}", idx + 1, files.len(), path.display()),
            Err(e) => eprintln!("❌ [{}/{}] 失败: {} 错误: {:?}", idx + 1, files.len(), path.display(), e),
        }
    }
}

fn main() -> Result<()> {
    println!("批量 ChaCha20-Poly1305 文件加密/解密 工具");

    let encrypt = prompt_mode()?;
    let dir_str = prompt_directory()?;
    let dir_path = Path::new(&dir_str);
    let password = prompt_password()?;

    let key = derive_key(&password, SALT)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    println!(
        "开始{}目录: {}",
        if encrypt { "加密" } else { "解密" },
        dir_path.display()
    );

    process_directory(dir_path, &cipher, encrypt);

    println!("所有文件处理完成。感谢使用！");
    Ok(())
}
