import json

def convert_to_c_string(text):
    """转义特殊字符为C字符串格式"""
    escape_dict = {
        '\\': r'\\',
        '"': r'\"',
    }
    # return ''.join(escape_dict.get(c, c) for c in text)
    return text

def process_file(input_path, output_path):
    """处理文件转换主函数"""
    # 读取输入文件
    with open(input_path, 'r', encoding='utf-8') as f:
        original_text = f.read()

    entries = []
    # 分割数据块
    for idx, block in enumerate(original_text.strip().split('---------------------')):
        if not block.strip():
            continue  # 跳过空块
        
        # 分割input/output
        parts = block.split('+++++++++++++++++++++', 1)
        if len(parts) != 2:
            print(f"警告：第 {idx+1} 个条目格式错误，已跳过")
            continue
        
        # 处理转义
        input_content = convert_to_c_string(parts[0].strip())
        output_content = convert_to_c_string(parts[1].strip())

        entries.append({
            "instruction": f"样例{len(entries)+1}",
            "input": input_content,
            "output": output_content
        })

    # 写入输出文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)

    print(f"转换完成！共处理 {len(entries)} 条数据，结果已保存至 {output_path}")

# 使用示例（修改以下路径）
if __name__ == "__main__":
    input_file = "./FineTune_Data/sample.bak"    # 输入文件路径
    output_file = "output.json" # 输出文件路径
    
    process_file(input_file, output_file)