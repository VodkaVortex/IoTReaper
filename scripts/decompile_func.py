# -*- coding: utf-8 -*-
from __future__ import print_function
# @category Analysis
# @description Decompile function with address mapping and save to file (Python 2 Compatible with print())
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decompile_function_with_addresses(func):
    """
    Safely decompile a function and return line-address mapping.
    Returns: list of (address, line_text)
    """
    iface = DecompInterface()
    iface.openProgram(currentProgram)
    result = iface.decompileFunction(func, 60, ConsoleTaskMonitor())

    if not result.decompileCompleted():
        print("❌ Failed to decompile: {}".format(func.getName()))
        return []

    lines = []
    decompiled = result.getDecompiledFunction()
    raw_code = decompiled.getC().splitlines()

    # fallback: associate each line with entry address (best-effort)
    addr = func.getEntryPoint()

    for line in raw_code:
        line = line.strip()
        if line:
            lines.append((addr, line))
            addr = addr.add(1)  # not exact, just for placeholder display

    return lines

def save_to_file(func_name, lines):
    filename = "{}_decompiled_with_addr.txt".format(func_name)
    with open(filename, "w") as f:
        f.write("Decompiled function: {}\n".format(func_name))
        f.write("=" * 50 + "\n")
        for addr, line in lines:
            f.write("{}: {}\n".format(addr, line))
    print("✅ Decompiled output saved to: {}".format(filename))

# ===================== Script Entry =====================p;;;;;;;;;;;;

if __name__ == '__main__':
    args = getScriptArgs()

    if not args:
        print("Usage: -postscript decompile_with_addr.py <func_name | 0xADDR>")
        exit(1)

    func_input = args[0]
    if func_input.startswith("0x") or func_input.isdigit():
        addr = toAddr(int(func_input, 16))
        func = getFunctionAt(addr)
    else:
        symbols = currentProgram.getSymbolTable().getSymbols(func_input)
        func = None
        for sym in symbols:
            if sym.getSymbolType().toString() == "FUNCTION":
                func = getFunctionAt(sym.getAddress())
                break

    if not func:
        print("❌ Function not found: {}".format(func_input))
        exit(1)

    print("🔍 Decompiling function: {}".format(func.getName()))
    lines = decompile_function_with_addresses(func)
    if lines:
        save_to_file(func.getName(), lines)
    else:
        print("⚠️ No decompiled lines found.")
