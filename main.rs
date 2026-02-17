[package]
name = "file_organizer"
version = "0.1.0"
authors = ["Your Name <you@example.com>"]
edition = "2018"

[dependencies]
walkdir = "2.3"      # 用于遍历目录树
regex = "1"          # 用于正则表达式处理
phf = "0.10"         # 用于高效的静态哈希映射

[profile.dev]
# 禁用调试信息，减少开发时构建文件大小
debug = false
opt-level = 3        # 使用最大优化，生成最小文件
lto = true           # 启用链接时间优化 (LTO)
panic = "abort"      # 禁用堆栈展开，进一步减小文件大小
codegen-units = 1    # 禁用并行代码生成，减少生成的二进制文件大小
strip = "debuginfo"  # 去除调试信息

[profile.release]
# 发布配置，确保压缩和最大优化
debug = false        # 禁用调试信息
opt-level = 3        # 最大优化
lto = true           # 启用链接时间优化
panic = "abort"      # 禁用堆栈展开
codegen-units = 1    # 单一代码生成单元，减少生成的二进制文件大小
strip = "debuginfo"  # 去除调试信息

[dependencies]
walkdir = "2.3"      # 遍历目录树
regex = "1"          # 正则表达式支持
phf = "0.10"         # 高效的静态哈希映射









use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use std::collections::HashMap;
use phf::phf_map;

#[derive(Debug)]
enum FileCategory {
    Office,
    Images,
    Videos,
    Audio,
}

const FILE_TYPE_EXTENSIONS: phf::Map<&'static str, Vec<&'static str>> = phf_map! {
    "Office" => vec![".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf"],
    "Images" => vec![".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
    "Videos" => vec![".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv"],
    "Audio"  => vec![".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a"],
};

// 判断文件是否属于某个分类
fn get_file_category(file_name: &str) -> Option<FileCategory> {
    let extension = Path::new(file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_lowercase();

    for (category, extensions) in FILE_TYPE_EXTENSIONS.iter() {
        if extensions.contains(&extension.as_str()) {
            match *category {
                "Office" => return Some(FileCategory::Office),
                "Images" => return Some(FileCategory::Images),
                "Videos" => return Some(FileCategory::Videos),
                "Audio"  => return Some(FileCategory::Audio),
                _ => continue,
            }
        }
    }
    None
}

// 确保目标目录存在
fn ensure_directory_exists(path: &Path) {
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            eprintln!("Error creating directory {}: {}", path.display(), e);
        }
    }
}

// 生成唯一的文件名，如果文件存在，添加数字后缀
fn generate_unique_filename(destination_directory: &Path, original_filename: &str) -> PathBuf {
    let mut counter = 1;
    let mut new_file_path = destination_directory.join(original_filename);

    while new_file_path.exists() {
        let mut new_filename = original_filename.to_string();
        if let Some(extension) = new_filename.rsplit_once('.') {
            new_filename = format!("{}_{}{}", extension.0, counter, extension.1);
        }
        new_file_path = destination_directory.join(new_filename);
        counter += 1;
    }

    new_file_path
}

// 处理文件的移动或复制
fn process_files(
    source_dirs: Vec<String>,
    target_dir: &Path,
    operation: &str,
) -> Result<(usize, usize), io::Error> {
    let mut total_files_processed = 0;    // 记录处理的文件数量
    let mut total_files_failed = 0;       // 记录失败的文件数量

    // 遍历源文件夹
    for source_dir in source_dirs {
        if !Path::new(&source_dir).exists() {
            eprintln!("Warning: source directory not found: {}", source_dir);
            continue;
        }

        for entry in WalkDir::new(&source_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_path = entry.path();
            if file_path.is_file() {
                let file_name = file_path.file_name().unwrap().to_string_lossy();

                // 获取文件类别
                if let Some(category) = get_file_category(&file_name) {
                    let category_dir = match category {
                        FileCategory::Office => "Office",
                        FileCategory::Images => "Images",
                        FileCategory::Videos => "Videos",
                        FileCategory::Audio => "Audio",
                    };

                    let destination_category_dir = target_dir.join(category_dir);
                    ensure_directory_exists(&destination_category_dir);

                    let unique_file_name = generate_unique_filename(
                        &destination_category_dir,
                        &file_name,
                    );

                    if operation == "move" {
                        if let Err(e) = fs::rename(file_path, &unique_file_name) {
                            eprintln!("Error moving file: {}", e);
                            total_files_failed += 1;
                        } else {
                            total_files_processed += 1;
                        }
                    } else if operation == "copy" {
                        if let Err(e) = fs::copy(file_path, &unique_file_name) {
                            eprintln!("Error copying file: {}", e);
                            total_files_failed += 1;
                        } else {
                            total_files_processed += 1;
                        }
                    }
                }
            }
        }
    }

    Ok((total_files_processed, total_files_failed))  // 返回处理成功与失败的文件数
}

// 获取用户输入源目录
fn prompt_for_source_directories() -> Vec<String> {
    print!("Enter one or more source folders (comma-separated): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().split(',').map(|s| s.trim().to_string()).collect()
}

// 获取目标目录
fn prompt_for_target_directory() -> String {
    print!("Enter target directory path: ");
    io::stdout().flush().unwrap();

    let mut target_dir = String::new();
    io::stdin().read_line(&mut target_dir).unwrap();
    target_dir.trim().to_string()
}

// 获取操作模式
fn prompt_for_operation_mode() -> String {
    loop {
        print!("Choose operation mode: type 'm' for move or 'c' for copy: ");
        io::stdout().flush().unwrap();

        let mut operation = String::new();
        io::stdin().read_line(&mut operation).unwrap();
        let operation = operation.trim().to_lowercase();
        if operation == "m" || operation == "move" {
            return "move".to_string();
        } else if operation == "c" || operation == "copy" {
            return "copy".to_string();
        }
        eprintln!("Invalid input. Please enter 'm' or 'c'.");
    }
}

// 显示交互式菜单
fn display_menu() {
    println!("\n=== File Organizer Menu ===");
    println!("1. Enter source directories");
    println!("2. Enter target directory");
    println!("3. Choose move or copy operation");
    println!("4. Start organizing");
    println!("5. Show current settings");
    println!("0. Exit");
    println!("===========================");
}

fn main() {
    let mut source_dirs: Vec<String> = Vec::new();
    let mut target_dir = String::new();
    let mut operation_mode = String::new();

    loop {
        display_menu();

        print!("Choose an option: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        match choice.trim() {
            "1" => {
                source_dirs = prompt_for_source_directories();
            }
            "2" => {
                target_dir = prompt_for_target_directory();
            }
            "3" => {
                operation_mode = prompt_for_operation_mode();
            }
            "4" => {
                if source_dirs.is_empty() || target_dir.is_empty() || operation_mode.is_empty() {
                    eprintln!("⚠️ Please make sure all settings are entered!");
                    continue;
                }
                let target_path = Path::new(&target_dir);
                match process_files(source_dirs.clone(), target_path, &operation_mode) {
                    Ok((processed, failed)) => {
                        println!("\nFile Organization Complete!");
                        println!("Processed: {}", processed);
                        println!("Failed: {}", failed);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            "5" => {
                println!("\nCurrent Settings:");
                println!("Source directories: {:?}", source_dirs);
                println!("Target directory: {}", target_dir);
                println!("Operation mode: {}", operation_mode);
            }
            "0" => {
                println!("Exiting...");
                break;
            }
            _ => {
                eprintln!("Invalid choice, please try again.");
            }
        }
    }
}
