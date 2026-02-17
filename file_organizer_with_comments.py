import os                                  # 导入 os 模块用于文件系统操作
import shutil                              # 导入 shutil 模块用于复制/移动文件

# file type extension mapping by category
FILE_TYPE_EXTENSIONS = {                   # 映射不同文件类型对应的扩展名
    "Office": ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf'],  # Office 类型扩展
    "Images": ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],   # 图片类型扩展
    "Videos": ['.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv'],             # 视频类型扩展
    "Audio":  ['.mp3', '.wav', '.aac', '.flac', '.ogg', '.m4a']             # 音频类型扩展
}

def ensure_directory_exists(directory_path):                               # 确保目录存在
    if not os.path.exists(directory_path):                                  # 如果路径不存在
        os.makedirs(directory_path)                                         # 创建目录

def find_file_category(file_name):                                          # 根据扩展名确定文件分类
    _, extension = os.path.splitext(file_name)                              # 拆分文件名获取扩展名
    extension = extension.lower()                                            # 扩展名转为小写
    for category, extension_list in FILE_TYPE_EXTENSIONS.items():           # 遍历所有分类
        if extension in extension_list:                                     # 如果扩展匹配
            return category                                                  # 返回分类字符串
    return None                                                              # 未匹配返回 None

def generate_unique_filename(destination_directory, original_filename):     # 生成唯一文件名避免冲突
    base_name, extension = os.path.splitext(original_filename)              # 拆分基本名和扩展名
    counter = 1                                                              # 初始化计数
    candidate_name = original_filename                                       # 候选名起始为原始名
    full_path = os.path.join(destination_directory, candidate_name)         # 组合完整路径

    while os.path.exists(full_path):                                         # 如果路径已存在同名文件
        candidate_name = f"{base_name}_{counter}{extension}"                 # 生成带计数的候选名
        full_path = os.path.join(destination_directory, candidate_name)     # 组合成新完整路径
        counter += 1                                                         # 计数器递增

    return candidate_name                                                    # 返回唯一文件名

def organize_files(source_directories, target_directory, operation_mode):    # 主整理函数
    total_files_processed = 0                                               # 统计处理的文件总数

    for source_dir in source_directories:                                   # 遍历所有源目录
        if not os.path.isdir(source_dir):                                    # 如果某个源不是有效目录
            print(f"Warning: source directory not found: {source_dir}")      # 警告路径无效
            continue                                                          # 继续下一个源目录

        for root_directory, subdirectories, files in os.walk(source_dir):    # 递归遍历目录及子目录
            for file_name in files:                                          # 遍历所有文件
                category = find_file_category(file_name)                      # 获取文件分类
                if category is None:                                         # 如果分类为空
                    continue                                                  # 跳过未分类文件

                source_file_path = os.path.join(root_directory, file_name)   # 拼接源路径
                destination_category_directory = os.path.join(target_directory, category)  # 拼接分类目标子目录
                ensure_directory_exists(destination_category_directory)      # 确保分类子目录存在

                unique_file_name = generate_unique_filename(                  # 生成不冲突的文件名
                    destination_category_directory, file_name
                )
                destination_file_path = os.path.join(                         # 最终目标路径
                    destination_category_directory, unique_file_name
                )

                try:
                    if operation_mode == "move":                              # 判断是移动模式
                        shutil.move(source_file_path, destination_file_path)    # 移动文件
                    else:                                                     # 否则为复制模式
                        shutil.copy2(source_file_path, destination_file_path)   # 复制文件

                    total_files_processed += 1                                 # 计数累加
                except Exception as exception_obj:                            # 捕获异常
                    print(f"Error processing {source_file_path}: {exception_obj}")  # 打印错误

    print(f"\nOperation complete. Total files handled: {total_files_processed}")  # 输出处理结果

def prompt_for_source_directories():                                          # 交互提示输入源目录
    print("Enter one or more source folder paths (comma-separated):")         # 提示信息
    user_input = input().strip()                                              # 读取用户输入
    source_list = [path.strip() for path in user_input.split(",") if path.strip()]  # 分割获取列表
    return source_list                                                        # 返回列表

def prompt_for_target_directory():                                            # 提示输入目标目录
    while True:                                                               # 循环直到有效输入
        print("Enter target directory path:")                                  # 提示
        target_path = input().strip()                                          # 获取输入
        if target_path:                                                       # 有效则返回
            return target_path

def prompt_for_operation_mode():                                              # 提示选择移动/复制
    while True:
        print("Choose operation mode: type 'm' for move or 'c' for copy:")     # 提示
        user_choice = input().strip().lower()                                  # 获取标准化输入
        if user_choice in ["m", "move"]:                                       # 选择移动
            return "move"                                                       # 返回 move
        if user_choice in ["c", "copy"]:                                       # 选择复制
            return "copy"                                                       # 返回 copy
        print("Invalid input. Please enter 'm' or 'c'.")                        # 错误重试提示

def main():                                                                   # 程序入口函数
    print("=== File Organizer with Conflict Resolution ===")                   # 标题

    source_directories = prompt_for_source_directories()                       # 询问源目录
    if not source_directories:                                                 # 无输入直接退出
        print("No source directories entered. Exiting.")
        return

    target_directory = prompt_for_target_directory()                           # 输入目标目录
    operation_mode = prompt_for_operation_mode()                               # 输入操作模式

    print("\nSummary of your input:")                                           # 总结信息
    print(f"  Source directories: {source_directories}")
    print(f"  Target directory: {target_directory}")
    print(f"  Operation mode: {operation_mode}")

    print("\nPress Enter to start, or type 'q' to cancel:")                     # 确认提示
    confirm = input().strip().lower()
    if confirm == "q":                                                         # 取消整理
        print("Operation cancelled.")
        return

    organize_files(source_directories, target_directory, operation_mode)       # 调用整理函数

if __name__ == "__main__":                                                    # 主程序执行判断
    main()                                                                     # 运行 main
