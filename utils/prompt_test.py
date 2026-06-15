def process_data(input_data):
    # 拆分输入数据为每个块
    blocks = input_data.split('---------------------')

    # 用于存储符合要求的结果
    valid_data = []

    # 遍历每个块
    for block in blocks:
        lines = block.strip().split('\n')
        
        # 如果块为空，则跳过
        if not lines:
            continue

        # 获取实际代码块（假设每个代码段被 '+++++++' 分隔）
        code_block = []
        for i, line in enumerate(lines):
            if line.strip() == '+++++++':
                if code_block:
                    # 判断代码段是否符合要求（长度小于6000）
                    code = ''.join(code_block).strip()
                    if len(code) < 6000:
                        valid_data.append('\n'.join(code_block))  # 保留符合条件的代码段
                    code_block = []  # 清空临时存储的代码段
            else:
                code_block.append(line.strip())  # 收集代码行

        # 如果最后一段代码没有被处理，手动检查并添加
        if code_block:
            code = ''.join(code_block).strip()
            if len(code) < 6000:
                valid_data.append('\n'.join(code_block))

    # 返回保留的数据块
    return '\n---------------------\n'.join(valid_data)


# 输入文件路径
input_file = '/home/satc/iotreaper/utils/callers.txt'

# 读取输入文件数据
try:
    with open(input_file, 'r') as file:
        input_data = file.read()
    print(f"成功读取文件: {input_file}")
except FileNotFoundError:
    print(f"错误: 文件 {input_file} 未找到！")
    exit(1)

# 调用函数处理数据
print("正在处理数据...")
output_data = process_data(input_data)

# 如果有有效的数据，保存到输出文件
if output_data:
    output_file = 'callers_output.txt'
    with open(output_file, 'w') as file:
        file.write(output_data)
    print(f"处理后的数据已保存至 {output_file}")
else:
    print("没有符合条件的数据，未生成输出文件。")
