# coding: utf-8
# @category Analysis
# @description Recursively search dangerous function calls (up to 5 layers deep)

from collections import defaultdict
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import TaskMonitor
from java.util import Base64
from java.lang import String
import json
import os 

# ===== CONFIG =====
MAX_DEPTH = 3
DANGEROUS_FUNCS = {"system", "popen", "execve", "execl"}
DANGEROUS_PARAM_POS = {
    "system": [0],
    "popen": [0],
    "execve": [0],
    "strcpy": [1],
    "sprintf": [1],
    "strcat": [1],
    "memcpy": [1],
    "execl": [0],
    "fopen": [0],
    "doSystemCmd": [0]
}
# ==================

visited_funcs = set()
dangerous_paths = defaultdict(list)

def get_func_by_name(func_name):
    symbols = currentProgram.getSymbolTable().getSymbols(func_name)
    for sym in symbols:
        if sym.getSymbolType() == SymbolType.FUNCTION:
            return getFunctionAt(sym.getAddress())
    return None

def get_callees(func):
    """Find all functions called by the given function."""
    callees = []
    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
    for inst in instructions:
        if inst.getFlowType().isCall():
            refs = inst.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isCall():
                    callee = getFunctionAt(ref.getToAddress())
                    if callee:
                        callees.append((inst.getAddress(), callee))
    return callees

def trace_dangerous_calls(func, depth=0, call_chain=None, origin_func=None):
    if not func or depth > MAX_DEPTH:
        return
    if call_chain is None:
        call_chain = []

    if origin_func is None:
        origin_func = func  # set once at root

    visited_funcs.add(func)

    callees = get_callees(func)
    for addr, callee in callees:
        step = (func, addr, callee)
        new_chain = call_chain + [step]

        if callee.getName() in DANGEROUS_FUNCS:
            dangerous_paths[origin_func].append(new_chain)
        else:
            if callee not in visited_funcs:
                trace_dangerous_calls(callee, depth + 1, new_chain, origin_func)

def print_results():
    print("\n=== Dangerous Call Path Analysis ===")
    for origin_func, paths in dangerous_paths.items():
        print("\n[Function: {}]".format(origin_func))
        for path in paths:
            for caller, addr, callee in path:
                print("  {} -> {} @ {}".format(caller, callee, addr))
            print("-" * 40)
    if not dangerous_paths:
        print("No dangerous calls found within {} levels.".format(MAX_DEPTH))


# ======== ENTRY POINT ========

if __name__ == '__main__':

    args = getScriptArgs()
    
    from java.sql import DriverManager

    # Connect to SQLite database
    db_path = args[2]
    conn = DriverManager.getConnection("jdbc:sqlite:" + db_path)

    if not args or len(args) < 2:
        print("Usage: -postscript script.py FUNC_NAME_BASE64")
        exit()

    file_format = currentProgram.getExecutableFormat()
    if "Link" in file_format:
        new_base_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0)
        currentProgram.setImageBase(new_base_addr, True)
    base_address = currentProgram.getImageBase()

    # Parse input parameters
    lib_name = args[0]
    base64_data = args[1]
    decoded_bytes = Base64.getDecoder().decode(base64_data)
    decoded_str = str(String(decoded_bytes, "utf-8"))
    data = json.loads(decoded_str)
    
    print("Parsed function address mappings, total:", len(data))

    for func_name, hex_addr in data.items():
        try:
            addr = toAddr(int(hex_addr, 16))
            func = getFunctionAt(addr)
            if not func:
                print("[WARN] Function not found:", func_name, "Address:", hex_addr)
                continue
            print("Analyzing function:", func_name, "@", addr)
            visited_funcs.clear()
            trace_dangerous_calls(func, origin_func=func)

        except Exception as e:
            print("[ERROR]", func_name, hex_addr, "failed to process:", str(e))

    # Save analysis results
    def save_results_to_json(output_path="/tmp/ghidra_dangerous_result.json"):
        result_data = []

        for origin_func, paths in dangerous_paths.items():
            origin_name = origin_func.getName()
            origin_address = str(origin_func.getEntryPoint())

            for path in paths:
                steps = []
                for caller_obj, call_addr, callee_obj in path:
                    steps.append([
                        [caller_obj.getName(), str(caller_obj.getEntryPoint())],
                        str(call_addr),
                        [callee_obj.getName(), str(callee_obj.getEntryPoint())]
                    ])
                result_data.append({
                    "origin": origin_name,
                    "origin_address": origin_address,
                    "steps": steps
                })

        # try:
        #     f = open(output_path, "w")
        #     json.dump(result_data, f, indent=2)
        #     f.close()
        #     print("[INFO] JSON result saved:", output_path)
        # except Exception as e:
        #     print("[ERROR] Failed to save JSON:", str(e))

        # Save result_data as full JSON text into SQLite
        try:
            json_text = json.dumps(result_data, indent=2)

            # Create table if not exists
            stmt = conn.createStatement()
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS lib_unsafe_res_json (
                    lib_file_name TEXT PRIMARY KEY,
                    result_json TEXT
                )
            """)
            stmt.close()

            # Insert or update JSON result
            insert_sql = """
                INSERT OR REPLACE INTO lib_unsafe_res_json(lib_file_name, result_json)
                VALUES (?, ?)
            """
            pstmt = conn.prepareStatement(insert_sql)
            pstmt.setString(1, lib_name)
            pstmt.setString(2, json_text)
            pstmt.executeUpdate()
            pstmt.close()

            print("[INFO] result_data successfully written to SQLite")
        except Exception as e:
            print("[ERROR] Failed to write result_data to SQLite:", str(e))

    save_results_to_json()
