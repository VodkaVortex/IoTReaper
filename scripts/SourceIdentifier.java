import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;

import java.util.*;
import java.util.regex.*;
import java.io.*;

public class SourceIdentifier extends GhidraScript {

    private static final Pattern FORMAT_PATTERN = Pattern.compile(".*%[0-9]*[sdxXcfegpn].*");
    private static final Pattern INVALID_CHAR_PATTERN = Pattern.compile(".*[,.>/&%].*");

    private static final Set<String> SYSTEM_FUNCTIONS = new HashSet<>(Arrays.asList(
        "printf", "fprintf", "sprintf", "snprintf", "puts", "fputs", "fwrite", "fread",
        "exit", "malloc", "free", "calloc", "realloc", "memcpy", "strcpy", "strncpy",
        "strlen", "strcmp", "strncmp", "perror", "atoi", "atol", "strtol", "system",
        "write", "read", "open", "close", "access", "chdir", "getcwd", "stat", "fstat",
        "sscanf", "scanf", "vfprintf", "vprintf", "vsnprintf", "vsprintf", "trace", "strstr", "popen"
    ));

    // Enhanced class to store function information including parent functions
    private static class FunctionInfo {
        private String name;
        private Address address;
        private List<String> codeLines;
        private int callCount;
        private Set<String> parentFunctions;  // 新增：存储调用该函数的父函数

        public FunctionInfo(String name, Address address) {
            this.name = name;
            this.address = address;
            this.codeLines = new ArrayList<>();
            this.callCount = 0;
            this.parentFunctions = new HashSet<>();
        }

        public String getName() { return name; }
        public Address getAddress() { return address; }
        public List<String> getCodeLines() { return codeLines; }
        public int getCallCount() { return callCount; }
        public Set<String> getParentFunctions() { return parentFunctions; }
        public int getParentCount() { return parentFunctions.size(); }
        
        public void incrementCallCount() { callCount++; }
        public void addParentFunction(String parentName) { 
            if (parentName != null) {
                parentFunctions.add(parentName); 
            }
        }
        
        public void addCodeLine(String line) {
            if (codeLines.size() < 3) {
                codeLines.add(line);
            }
        }
    }

    private Map<String, FunctionInfo> calleeToFunctionInfo = new LinkedHashMap<>();
    private Map<String, Address> stringAddrMap = new HashMap<>();
    private Map<Function, String> decompiledCache = new HashMap<>();
    private String outputDir = ".";  // Default to current directory

    @Override
    public void run() throws Exception {
        displayBaseAddressInfo();

        // Check if the output directory is passed as a parameter
        if (getScriptArgs().length > 0) {
            outputDir = getScriptArgs()[0];  // Set output directory from the script arguments
        }

        long start = System.currentTimeMillis();

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(currentProgram)) {
            println("Failed to open program.");
            return;
        }

        // Step 1: Collect valid strings
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (data.isDefined() && data.getValue() instanceof String) {
                String value = (String) data.getValue();
                if (value.length() < 2 || value.length() > 128) continue;
                if (FORMAT_PATTERN.matcher(value).matches()) continue;
                if (INVALID_CHAR_PATTERN.matcher(value).matches()) continue;
                stringAddrMap.put(value, data.getAddress());
            }
        }

        // Step 2: Reference analysis
        for (Map.Entry<String, Address> entry : stringAddrMap.entrySet()) {
            String str = entry.getKey();
            Address strAddr = entry.getValue();

            for (Reference ref : getReferencesTo(strAddr)) {
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                if (func == null) continue;

                String cCode = decompiledCache.get(func);
                if (cCode == null) {
                    DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
                    if (!results.decompileCompleted()) continue;
                    cCode = results.getDecompiledFunction().getC();
                    decompiledCache.put(func, cCode);
                }

                for (String line : cCode.split("\n")) {
                    String trimmed = line.trim();
                    if (!containsTargetString(trimmed, str)) continue;

                    String callee = extractCalledFunction(trimmed, str);
                    if (callee == null || SYSTEM_FUNCTIONS.contains(callee)) continue;

                    // Find the called function to get its address
                    Function calledFunction = findFunctionByName(callee);
                    Address calleeAddress = (calledFunction != null) ? calledFunction.getEntryPoint() : null;

                    // Get or create FunctionInfo
                    FunctionInfo funcInfo = calleeToFunctionInfo.get(callee);
                    if (funcInfo == null) {
                        funcInfo = new FunctionInfo(callee, calleeAddress);
                        calleeToFunctionInfo.put(callee, funcInfo);
                    }

                    funcInfo.addCodeLine(trimmed);
                    funcInfo.incrementCallCount();
                    // 新增：记录父函数
                    funcInfo.addParentFunction(func.getName());

                    break; // Each string only adds one line in that function
                }
            }
        }

        decompiler.dispose();

        // Step 3: Save results to the specified directory with the fixed filename
        saveResultsToFile();

        long end = System.currentTimeMillis();
        println("Saved to " + outputDir + "/strings_calls.txt");
        println("Total analysis time: " + (end - start) + " ms");
        
        // 新增：打印统计信息
        printStatistics();
    }

    private void displayBaseAddressInfo() {
        println("\n\uD83D\uDCCD Base Address Information:");
        
        // 获取当前基址
        Address currentBaseAddr = currentProgram.getImageBase();
        println("  Current Image Base: " + currentBaseAddr);
        
        // 检查是否为共享库
        String fileName = currentProgram.getName();
        boolean isSharedLibrary = fileName.endsWith(".so");
        println("  File Name: " + fileName);
        println("  Is Shared Library: " + isSharedLibrary);
        
        // 获取地址工厂信息
        AddressFactory addrFactory = currentProgram.getAddressFactory();
        println("  Default Address Space: " + addrFactory.getDefaultAddressSpace().getName());
        
        // 获取所有地址空间
        AddressSpace[] spaces = addrFactory.getAllAddressSpaces();
        println("  Available Address Spaces:");
        for (AddressSpace space : spaces) {
            println("    - " + space.getName() + " (Size: " + space.getSize() + " bits)");
        }
        
        // 获取程序格式信息
        String fileFormat = currentProgram.getExecutableFormat();
        println("  Executable Format: " + fileFormat);
        
        // 获取内存布局信息
        println("  Memory Layout:");
        for (AddressSpace space : spaces) {
            if (space.isMemorySpace()) {
                Address minAddr = space.getMinAddress();
                Address maxAddr = space.getMaxAddress();
                println("    " + space.getName() + ": " + minAddr + " - " + maxAddr);
            }
        }
        
        // 对于共享库，检查是否需要调整基址
        if (isSharedLibrary && currentBaseAddr.getOffset() == 0) {
            println("  ⚠️ Shared library with zero base address detected!");
            println("  Consider setting a non-zero base address for analysis.");
        }
        
        println(""); // 空行分隔
    }
    
    private Function findFunctionByName(String functionName) {
        // Try to find function by name in the current program
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcManager.getFunctions(true);
        
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (func.getName().equals(functionName)) {
                return func;
            }
        }
        
        // Also try to find by symbol name
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbols(functionName);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                return funcManager.getFunctionAt(symbol.getAddress());
            }
        }
        
        return null;
    }

    private boolean containsTargetString(String line, String targetStr) {
        if (line.contains("\"" + targetStr + "\"")) return true;
        Pattern pattern = Pattern.compile("\\b" + Pattern.quote(targetStr) + "\\b");
        return pattern.matcher(line).find();
    }

    private String extractCalledFunction(String line, String targetStr) {
        String patternStr = "(\\w+)\\s*\\([^)]*\"?" + Pattern.quote(targetStr) + "\"?[^)]*\\)";
        Matcher matcher = Pattern.compile(patternStr).matcher(line);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private void saveResultsToFile() {
        File outputFile = new File(outputDir, "strings_calls.txt");

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            for (Map.Entry<String, FunctionInfo> entry : calleeToFunctionInfo.entrySet()) {
                FunctionInfo funcInfo = entry.getValue();
                writer.println("Call: " + funcInfo.getName());
                
                // Output the function address
                if (funcInfo.getAddress() != null) {
                    writer.println("Address: " + funcInfo.getAddress().toString());
                } else {
                    writer.println("Address: Not found");
                }
                
                writer.println("num: " + funcInfo.getCallCount());
                
                // 新增：输出父函数数量和列表
                writer.println("Parent Functions Count: " + funcInfo.getParentCount());
                if (funcInfo.getParentCount() > 0) {
                    writer.println("Parent Functions: " + String.join(", ", funcInfo.getParentFunctions()));
                }
                
                for (String line : funcInfo.getCodeLines()) {
                    writer.println("  " + line);
                }
                writer.println();
            }
        } catch (IOException e) {
            println("Error writing file: " + e.getMessage());
        }
    }
    
    // 新增：打印统计信息方法
    private void printStatistics() {
        println("\n📊 Function Call Statistics:");
        println("Total functions analyzed: " + calleeToFunctionInfo.size());
        
        // 按父函数数量排序
        List<FunctionInfo> sortedByParents = new ArrayList<>(calleeToFunctionInfo.values());
        sortedByParents.sort((a, b) -> Integer.compare(b.getParentCount(), a.getParentCount()));
        
        println("\nTop 10 functions by parent count:");
        for (int i = 0; i < Math.min(10, sortedByParents.size()); i++) {
            FunctionInfo func = sortedByParents.get(i);
            println("  " + func.getName() + ": " + func.getParentCount() + " parents, " + func.getCallCount() + " calls");
        }
        
        // 按调用次数排序
        sortedByParents.sort((a, b) -> Integer.compare(b.getCallCount(), a.getCallCount()));
        
        println("\nTop 10 functions by call count:");
        for (int i = 0; i < Math.min(10, sortedByParents.size()); i++) {
            FunctionInfo func = sortedByParents.get(i);
            println("  " + func.getName() + ": " + func.getCallCount() + " calls, " + func.getParentCount() + " parents");
        }
    }
}