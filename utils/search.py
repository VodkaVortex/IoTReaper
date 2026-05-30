import sqlite3
import json
import os

db_path = "/home/satc/liva/result/Trendnet-TEW824DRU/ghidra_analyze_res.db"
output_file = "callchain_decompile_result.txt"  # 输出文件名

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

with open(output_file, "w", encoding="utf-8") as f:
    cursor.execute("SELECT lib_file_name, result_json FROM lib_unsafe_res_json")
    rows = cursor.fetchall()

    for lib_file_name, result_json in rows:
        try:
            callchains = json.loads(result_json)
        except json.JSONDecodeError:
            print(f"解析 JSON 失败: {lib_file_name}")
            continue

        for chain in callchains:
            steps = chain.get("steps", [])
            if not steps:
                continue

            # 提取完整调用链
            func_chain = []
            addr_chain = []
            origin_func = steps[0][0][0]

            for step in steps:
                caller, caller_addr = step[0]
                callee, callee_addr = step[2]

                if not func_chain:  # 第一次加入 caller
                    func_chain.append(caller)
                    addr_chain.append(caller_addr)

                if callee not in func_chain:  # 避免重复
                    func_chain.append(callee)
                    addr_chain.append(callee_addr)

            # 查询每个函数的反编译代码
            decompiled_map = {}
            for func in func_chain:
                cursor.execute("""
                    SELECT decompiled_code FROM lib_decompile_res
                    WHERE lib_name = ? AND func_name = ?
                """, (lib_file_name, func))
                row = cursor.fetchone()
                decompiled_map[func] = row[0] if row else "N/A"

            # 写入文件
            f.write(f"[LIB] {lib_file_name}\n")
            f.write(f"Origin: {origin_func}\n")
            f.write(f"Chain: {' -> '.join(func_chain)}\n")
            f.write(f"Addresses: {' -> '.join(addr_chain)}\n\n")

            for func in func_chain:
                f.write(f"[{func}]\n")
                f.write(decompiled_map[func])
                f.write("\n\n")

            f.write("=" * 80 + "\n\n")

conn.close()

print(f"✅ 结果已保存到 {output_file}")
