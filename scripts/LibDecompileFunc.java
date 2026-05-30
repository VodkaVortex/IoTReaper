// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;

import java.sql.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import java.util.Base64;

public class LibDecompileFunc extends GhidraScript {

    private DecompInterface decompInterface;
    private static String DB_URL = "jdbc:sqlite:/tmp/ghidra_decompile.db";  // 默认，可通过参数替换
    private Map<String, String> addrToSymbolMap = new HashMap<>();

    private static class CallSite {
        Address address;
        String functionName;
        String mnemonic;

        CallSite(Address addr, String name, String mnem) {
            this.address = addr;
            this.functionName = name;
            this.mnemonic = mnem;
        }
    }

    @Override
    public void run() throws Exception {
        // 修正 image base（针对部分链接文件）
        String fileFormat = currentProgram.getExecutableFormat();
        if (fileFormat.contains("Link")) {
            Address newBaseAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0);
            currentProgram.setImageBase(newBaseAddr, true);
        }

        // 参数检查
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("Usage: -postScript LibDecompileFunc.java <lib_name> <base64_func_data> <db_path>");
            return;
        }

        String libName = args[0];
        String base64Data = args[1];
        DB_URL = "jdbc:sqlite:" + args[2];

        // 创建表并清理旧数据
        createTable();
        clearOldData(libName);

        // Base64 解码 JSON
        byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
        String decodedStr = new String(decodedBytes, StandardCharsets.UTF_8);
        println("Decoded base64 string: " + decodedStr);
        // 触发重新分析，确保符号更新
        println("Running auto-analysis...");
        currentProgram.flushEvents();
        analyzeChanges(currentProgram); // ✅ 替代 AutoAnalysisManager

 

        JSONArray dataArray = new JSONArray(decodedStr);

        // **触发重新分析，确保符号最新**
        println("Refreshing analysis...");
        currentProgram.flushEvents();
        analyzeChanges(currentProgram); // ✅ 替代 AutoAnalysisManager

        // 构建地址->符号名映射
        buildAddressSymbolMap();

        // 初始化反编译器
        decompInterface = getDecompInterface();

        StringBuilder output = new StringBuilder();

        for (int i = 0; i < dataArray.length(); i++) {
            String item = dataArray.getString(i);
            String[] parts = item.split("\\|");
            if (parts.length != 2) continue;

            String funcName = parts[0];
            String addrStr = parts[1];

            Address addr = parseAddressString(addrStr);
            if (addr == null) {
                println("❌ Invalid address: " + addrStr);
                continue;
            }

            Function func = getFunctionAt(addr);
            if (func == null) {
                println("❌ Function not found at: " + addrStr);
                continue;
            }

            // output.append(String.format("Function: %s @ %s\n", func.getName(), func.getEntryPoint()));

            // 反编译
            DecompileResults results = decompInterface.decompileFunction(func, 60, monitor);
            if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
                output.append("Failed to decompile function.\n");
                continue;
            }

            String decompiledCode = results.getDecompiledFunction().getC();
            // println(decompiledCode);
            // 修正函数名
            String correctedCode = replaceFunctionHeaderName(decompiledCode, func.getName());

            // 添加行号
            String numberedCode = addLineNumbers(correctedCode);

            // 替换 FUN_xxx 为真实符号名
            String replacedSymbols = replaceUnknownFunctions(numberedCode);

            // 标注调用地址
            List<CallSite> callSites = extractCallSites(func);
            String annotatedCode = annotateDecompiledCode(replacedSymbols, callSites);

            // output.append(annotatedCode).append("\n");

            // 插入数据库
            insertDecompiledFunction(libName, item, annotatedCode);
        }

        println(output.toString());
    }

    // 初始化反编译器
    private DecompInterface getDecompInterface() {
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            throw new RuntimeException("❌ Failed to initialize decompiler: " + ifc.getLastMessage());
        }
        return ifc;
    }

    // 地址解析
    private Address parseAddressString(String addrStr) {
        try {
            if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
                long value = Long.parseLong(addrStr.substring(2), 16);
                return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            } else if (addrStr.matches("[0-9a-fA-F]+") && addrStr.length() <= 8) {
                long value = Long.parseLong(addrStr, 16);
                return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            } else if (addrStr.matches("\\d+")) {
                long value = Long.parseLong(addrStr);
                return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            } else {
                return parseAddress(addrStr);
            }
        } catch (Exception e) {
            return null;
        }
    }

    // 提取调用点信息
    private List<CallSite> extractCallSites(Function func) {
        List<CallSite> callSites = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        InstructionIterator instIter = listing.getInstructions(func.getBody(), true);

        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            if (inst.getFlowType().isCall() || inst.getMnemonicString().toLowerCase().contains("call")) {
                Address addr = inst.getAddress();
                Address to = null;

                for (Reference ref : inst.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        to = ref.getToAddress();
                        break;
                    }
                }

                String callee = "UNKNOWN";
                if (to != null) {
                    Function f = getFunctionAt(to);
                    if (f == null) {
                        f = createFunction(to, null);
                    }
                    if (f != null) callee = f.getName();
                    else {
                        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(to);
                        if (sym != null) callee = sym.getName();
                    }
                }

                callSites.add(new CallSite(addr, callee, inst.getMnemonicString()));
            }
        }
        return callSites;
    }

    // 标注调用地址
    private String annotateDecompiledCode(String cCode, List<CallSite> callSites) {
        StringBuilder out = new StringBuilder();
        String[] lines = cCode.split("\n");
        int callIndex = 0;

        for (String line : lines) {
            String trimmed = line.trim();
            boolean isCall = trimmed.contains("(") && trimmed.contains(");") && !trimmed.startsWith("//") &&
                             !trimmed.startsWith("/*") && !trimmed.equals("{") && !trimmed.equals("}");

            if (isCall && callIndex < callSites.size()) {
                CallSite cs = callSites.get(callIndex);
                if (trimmed.contains(cs.functionName)) {
                    out.append(String.format("0x%X: %s\n", cs.address.getOffset(), line));
                    callIndex++;
                    continue;
                }
            }
            out.append("            ").append(line).append("\n");
        }
        return out.toString();
    }

    // 添加行号
    private String addLineNumbers(String code) {
        StringBuilder numbered = new StringBuilder();
        String[] lines = code.split("\n");
        for (int i = 0; i < lines.length; i++) {
            numbered.append(String.format("%4d | %s\n", i + 1, lines[i]));
        }
        return numbered.toString();
    }


    // 修正函数名
    private String replaceFunctionHeaderName(String decompiledCode, String funcName) {
        return decompiledCode.replaceFirst("(?s)(?m)^.*?\\(", funcName + "(");
    }

    // 构建地址->符号名映射
    private void buildAddressSymbolMap() {
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.getAddress() != null && sym.getName() != null) {
                addrToSymbolMap.put(sym.getAddress().toString(), sym.getName());
            }
        }
    }

    // 替换 FUN_xxx 为真实符号名
    private String replaceUnknownFunctions(String code) {
        String result = code;
        for (Map.Entry<String, String> entry : addrToSymbolMap.entrySet()) {
            String symbolName = entry.getValue();
            if (symbolName.startsWith("FUN_")) continue;
            result = result.replaceAll("FUN_[0-9a-fA-F]+", symbolName);
        }
        return result;
    }

    // SQLite 连接
    private static Connection connect() {
        try {
            return DriverManager.getConnection(DB_URL);
        } catch (SQLException e) {
            System.err.println("❌ SQLite connection error: " + e.getMessage());
            return null;
        }
    }

    // 创建表
    private void createTable() {
        String sql = "CREATE TABLE IF NOT EXISTS lib_decompile_res (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "lib_name TEXT," +
                     "func_name TEXT," +
                     "func_addr TEXT," +
                     "decompiled_code TEXT NOT NULL," +
                     "UNIQUE(lib_name, func_name, func_addr)" +
                     ");";
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            println("❌ Error creating table: " + e.getMessage());
        }
    }

    // 清理旧数据
    private void clearOldData(String libName) {
        String sql = "DELETE FROM lib_decompile_res WHERE lib_name = ?";
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, libName);
            pstmt.executeUpdate();
            println("✅ Cleared old data for library: " + libName);
        } catch (SQLException e) {
            println("❌ Error clearing old data: " + e.getMessage());
        }
    }

    // 插入反编译结果
    private void insertDecompiledFunction(String libName, String funcName, String decompiledCode) {
        String sql = "INSERT OR REPLACE INTO lib_decompile_res(lib_name, func_name, func_addr, decompiled_code) VALUES(?, ?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, libName);
            pstmt.setString(2, funcName.split("\\|")[0]);
            pstmt.setString(3, funcName.split("\\|")[1]);
            pstmt.setString(4, decompiledCode);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            println("❌ Error inserting function: " + e.getMessage());
        }
    }
}
