// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;

import java.sql.*;
import java.util.*;
import java.io.*;
import org.json.*;
import ghidra.util.exception.*;

public class DangerFlowAnalyzer extends GhidraScript {

    private static final int MAX_DEPTH = 5;
    private Set<Address> sourceAddrs = new HashSet<>();
    private Map<Address, String> sinkAddrToName = new HashMap<>();
    private Set<String> sinkNames = new HashSet<>();
    private Map<Function, List<CallPath>> dangerousPaths = new HashMap<>();
    private Set<Function> processedFunctions = new HashSet<>();
    private String dbPath;

    private int totalPathsFound = 0;
    private int totalFunctionsAnalyzed = 0;

    // ===== 唯一调用统计（原有） =====
    private Set<String> uniqueCallRecords = new HashSet<>();  // "caller@callAddr->callee"
    private Map<Function, Integer> parentFunctionCallCount = new HashMap<>();
    private Map<Function, Set<Function>> parentToChildren = new HashMap<>();
    private Map<Integer, Integer> pathLengthDistribution = new HashMap<>();
    private Set<Function> allFunctionsInChains = new HashSet<>();
    private Map<Function, Integer> functionFrequency = new HashMap<>();
    private Map<String, CallSiteInfo> uniqueCallSites = new HashMap<>();

    // ===== 修正：只记录危险调用链中的父→子→{调用地址集合} =====
    private Map<Function, Map<Function, Set<Address>>> parentChildAddrs = new HashMap<>();

    // ======== 数据类 ========
    static class CallSiteInfo {
        Function caller;
        Address callAddr;
        Function callee;
        int pathCount; // 有多少条路径经过这个调用点

        CallSiteInfo(Function caller, Address callAddr, Function callee) {
            this.caller = caller;
            this.callAddr = callAddr;
            this.callee = callee;
            this.pathCount = 1;
        }
    }

    static class CallPath {
        List<CallStep> steps = new ArrayList<>();
        Function sourceFunction;
        Function sinkFunction;
        Address sinkCallAddress;  // 记录 sink 的调用地址
        int depth;
    }

    static class CallStep {
        Function caller;
        Address callAddr;
        Function callee;

        CallStep(Function caller, Address callAddr, Function callee) {
            this.caller = caller;
            this.callAddr = callAddr;
            this.callee = callee;
        }
    }

    @Override
    public void run() throws Exception {
        println("🔍 Starting Danger Flow Analysis...");

        displayBaseAddressInfo();

        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: -postScript DangerFlowAnalyzer.java <sqlite_path> <save_path>");
            return;
        }

        dbPath = args[0];
        String savePath = args[1];

        // 确保保存路径存在
        File saveDir = new File(savePath);
        if (!saveDir.exists()) {
            saveDir.mkdirs();
            println("📁 Created save directory: " + savePath);
        }

        try {
            readSourceAndSinkFromDB();
            renameSinkFunctions();
            Set<Function> entryFunctions = findEntryFunctions();
            println("📊 Found " + entryFunctions.size() + " entry functions");
            analyzeFlowPaths(entryFunctions);

            // 唯一调用统计
            analyzeUniqueCallStatistics();

            printStatistics();
            exportDangerousCallerCalleeChains(new File(savePath, "callers.txt").getAbsolutePath());
            exportUniqueCallStatistics(new File(savePath, "unique_call_statistics.txt").getAbsolutePath());
            exportDetailedPathsAndFunctions(new File(savePath, "detailed_analysis.txt").getAbsolutePath());
            exportPathsToCSV(new File(savePath, "paths_data.csv").getAbsolutePath());

            // 导出"危险调用链中的父→子→调用地址集合"
            exportParentChildCallsToJSON(new File(savePath, "parent_child_calls.json").getAbsolutePath());
            exportParentChildCallsToCSV(new File(savePath, "parent_child_calls.csv").getAbsolutePath());

            // 唯一调用点信息
            exportUniqueCallSites(new File(savePath, "unique_call_sites.csv").getAbsolutePath());

        } catch (Exception e) {
            printerr("❌ Analysis failed: " + e.getMessage());
            e.printStackTrace();
        }

        println("✅ Analysis complete.");
        println("📁 All results saved to: " + savePath);
        println("   - callers.txt: Decompiled caller-callee chains");
        println("   - unique_call_statistics.txt: Unique call statistical summary");
        println("   - detailed_analysis.txt: Detailed paths and functions");
        println("   - paths_data.csv: Structured path data");
        println("   - parent_child_calls.json: Parent→Child call addresses in danger chains (hierarchical JSON)");
        println("   - parent_child_calls.csv: Parent→Child call addresses in danger chains (flat CSV)");
        println("   - unique_call_sites.csv: Unique call sites information");
    }

    private void displayBaseAddressInfo() {
        println("\n📍 Base Address Information:");

        Address currentBaseAddr = currentProgram.getImageBase();
        println("  Current Image Base: " + currentBaseAddr);

        String fileName = currentProgram.getName();
        boolean isSharedLibrary = fileName.endsWith(".so");
        println("  File Name: " + fileName);
        println("  Is Shared Library: " + isSharedLibrary);

        AddressFactory addrFactory = currentProgram.getAddressFactory();
        println("  Default Address Space: " + addrFactory.getDefaultAddressSpace().getName());

        AddressSpace[] spaces = addrFactory.getAllAddressSpaces();
        println("  Available Address Spaces:");
        for (AddressSpace space : spaces) {
            println("    - " + space.getName() + " (Size: " + space.getSize() + " bits)");
        }

        String fileFormat = currentProgram.getExecutableFormat();
        println("  Executable Format: " + fileFormat);

        println("  Memory Layout:");
        for (AddressSpace space : spaces) {
            if (space.isMemorySpace()) {
                Address minAddr = space.getMinAddress();
                Address maxAddr = space.getMaxAddress();
                println("    " + space.getName() + ": " + minAddr + " - " + maxAddr);
            }
        }

        if (isSharedLibrary && currentBaseAddr.getOffset() == 0) {
            println("  ⚠️ Shared library with zero base address detected!");
            println("  Consider setting a non-zero base address for analysis.");
        }

        println("");
    }

    private void readSourceAndSinkFromDB() throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT tag, data FROM project_info WHERE tag IN ('source', 'sink')");

            while (rs.next()) {
                String tag = rs.getString("tag");
                String data = rs.getString("data");
                JSONArray arr = new JSONArray(data);

                if ("source".equals(tag)) parseSourceAddresses(arr);
                else if ("sink".equals(tag)) parseSinkNamesAndAddrs(arr);
            }
        }
    }

    private void parseSourceAddresses(JSONArray arr) {
        println("\n🔍 Parsing " + arr.length() + " sources (name/address mixed supported):");

        int added = 0, failed = 0;
        for (int i = 0; i < arr.length(); i++) {
            try {
                String raw = arr.getString(i).trim();
                String token = raw;
                String[] parts = raw.split("\\|");
                if (parts.length == 2) {
                    String maybeName = parts[0].trim();
                    String maybeAddr = parts[1].trim();
                    boolean ok = tryAddByToken(maybeAddr);
                    if (!ok) ok = tryAddByToken(maybeName);
                    if (!ok) {
                        failed++;
                        println("    ❌ Fail: " + raw);
                    } else added++;
                } else {
                    boolean ok = tryAddByToken(token);
                    if (!ok) {
                        failed++;
                        println("    ❌ Fail: " + raw);
                    } else added++;
                }
            } catch (Exception e) {
                failed++;
                println("  ⚠️ Failed to parse source item #" + i + ": " + e.getMessage());
            }
        }

        println("  ✅ Added source addresses: " + added);
        println("  🚫 Failed items: " + failed);
        println("  Total source addresses resolved (unique): " + sourceAddrs.size());
    }

    /**
     * 尝试把一个“地址或函数名”加入 sourceAddrs：
     * - 若是十六进制地址（支持带/不带 0x），直接解析到 Address 并找函数；
     * - 否则当作函数名，用 getGlobalFunctions(name) 解析（可能返回多个）。
     * 返回是否成功添加至少一个地址。
     */
    private boolean tryAddByToken(String token) {
        if (token == null) return false;
        String t = token.trim();
        if (t.isEmpty()) return false;

        // 1) 处理 "sub_xxxx" 形式
        if (t.startsWith("sub_") && t.length() > 4) {
            String hex = t.substring(4);
            if (hex.matches("[0-9A-Fa-f]+")) {
                try {
                    long val = Long.parseLong(hex, 16);

                    Address addr = null;
                    Function func = null;

                    // a) 绝对地址解析
                    try {
                        addr = toAddr(val);
                        func = getFunctionAt(addr);
                        if (func != null) {
                            sourceAddrs.add(func.getEntryPoint());
                            println("    ✅ Source by 'sub_xxxx' (absolute addr): " +
                                    func.getName() + " @ " + func.getEntryPoint());
                            return true;
                        }
                    } catch (Exception ignored) {}

                    // b) 基址相对解析
                    try {
                        Address baseAddr = currentProgram.getImageBase();
                        addr = baseAddr.add(val);
                        func = getFunctionAt(addr);
                        if (func != null) {
                            sourceAddrs.add(func.getEntryPoint());
                            println("    ✅ Source by 'sub_xxxx' (base-relative addr): " +
                                    func.getName() + " @ " + func.getEntryPoint());
                            return true;
                        }
                    } catch (Exception ignored) {}

                    // c) 遍历 AddressSpace
                    AddressFactory factory = currentProgram.getAddressFactory();
                    for (AddressSpace space : factory.getAllAddressSpaces()) {
                        if (!space.isMemorySpace()) continue;
                        try {
                            addr = space.getAddress(val);
                            func = getFunctionAt(addr);
                            if (func != null) {
                                sourceAddrs.add(func.getEntryPoint());
                                println("    ✅ Source by 'sub_xxxx' (addr in space '" +
                                        space.getName() + "'): " +
                                        func.getName() + " @ " + func.getEntryPoint());
                                return true;
                            }
                        } catch (Exception ignored) {}
                    }
                    return false;
                } catch (NumberFormatException e) {
                    println("    ⚠️ Invalid hex value in '" + t + "'");
                    return false;
                }
            }
        }

        // 2) 按十六进制地址解析（非 sub_xxxx）
        try {
            String hex = t.startsWith("0x") || t.startsWith("0X") ? t.substring(2) : t;
            if (hex.matches("(?i)[0-9a-f]+")) {
                long val = Long.parseLong(hex, 16);

                Address addr = null;
                Function func = null;

                // a) 绝对地址解析
                try {
                    addr = toAddr(val);
                    func = getFunctionAt(addr);
                    if (func != null) {
                        sourceAddrs.add(func.getEntryPoint());
                        println("    ✅ Source by absolute addr: " +
                                func.getName() + " @ " + func.getEntryPoint());
                        return true;
                    }
                } catch (Exception ignored) {}

                // b) 基址相对解析
                try {
                    Address baseAddr = currentProgram.getImageBase();
                    addr = baseAddr.add(val);
                    func = getFunctionAt(addr);
                    if (func != null) {
                        sourceAddrs.add(func.getEntryPoint());
                        println("    ✅ Source by base-relative addr: " +
                                func.getName() + " @ " + func.getEntryPoint());
                        return true;
                    }
                } catch (Exception ignored) {}

                // c) 遍历 AddressSpace
                AddressFactory factory = currentProgram.getAddressFactory();
                for (AddressSpace space : factory.getAllAddressSpaces()) {
                    if (!space.isMemorySpace()) continue;
                    try {
                        addr = space.getAddress(val);
                        func = getFunctionAt(addr);
                        if (func != null) {
                            sourceAddrs.add(func.getEntryPoint());
                            println("    ✅ Source by addr in space '" +
                                    space.getName() + "': " +
                                    func.getName() + " @ " + func.getEntryPoint());
                            return true;
                        }
                    } catch (Exception ignored) {}
                }

                return false;
            }
        } catch (Exception ignored) {}

        // 3) 按函数名解析（这里加入 external → thunk 处理）
        try {
            List<Function> fs = getGlobalFunctions(t);
            if (fs == null || fs.isEmpty()) {
                SymbolTable st = currentProgram.getSymbolTable();
                SymbolIterator it = st.getSymbolIterator(t, true);
                List<Function> bySym = new ArrayList<>();
                while (it.hasNext()) {
                    Symbol s = it.next();
                    if (s.getName().equals(t)) {
                        Function f = getFunctionAt(s.getAddress());
                        if (f != null) bySym.add(f);
                    }
                }
                fs = bySym;
            }

            if (fs != null && !fs.isEmpty()) {
                int cnt = 0;
                FunctionManager fm = currentProgram.getFunctionManager();

                for (Function f : fs) {
                    if (f.isExternal()) {
                        // external → 找所有 thunk
                        int thunkCnt = 0;
                        FunctionIterator fit = fm.getFunctions(true);
                        while (fit.hasNext()) {
                            Function tf = fit.next();
                            if (tf.isThunk() && tf.getThunkedFunction(true) == f) {
                                sourceAddrs.add(tf.getEntryPoint());
                                thunkCnt++;
                            }
                        }

                        if (thunkCnt > 0) {
                            println("    ✅ Source by external name via " + thunkCnt +
                                    " thunks for " + f.getName());
                            cnt += thunkCnt;
                        } else {
                            sourceAddrs.add(f.getEntryPoint());
                            cnt++;
                            println("    ⚠️ External source with no thunks: " +
                                    f.getName() + " @ " + f.getEntryPoint());
                        }
                    } else {
                        sourceAddrs.add(f.getEntryPoint());
                        cnt++;
                    }
                }

                if (cnt == 1) {
                    println("    ✅ Source by name: " + fs.get(0).getName() +
                            " (total addresses added: " + cnt + ")");
                } else {
                    println("    ✅ Source by name: " + t +
                            " → " + cnt + " addresses added");
                }
                return true;
            } else {
                println("    ⚠️ No function found for name: " + t);
                return false;
            }
        } catch (Exception e) {
            println("    ⚠️ Name resolution error for '" + t + "': " + e.getMessage());
            return false;
        }
    }

    private void parseSinkNamesAndAddrs(JSONArray arr) {
        println("\n🔍 Parsing " + arr.length() + " sink addresses:");

        for (int i = 0; i < arr.length(); i++) {
            String line = arr.getString(i);
            try {
                String[] parts = line.split("\\|");
                if (parts.length >= 2) {
                    String name = parts[0];
                    String addrStr = parts[1].replace("0x", "");
                    long addrValue = Long.parseLong(addrStr, 16);

                    println("  Trying to resolve sink '" + name + "': 0x" + addrStr);

                    Address addr = null;
                    Function func = null;
                    boolean resolved = false;

                    Address[] candidates = {
                        toAddr(addrValue),
                        currentProgram.getImageBase().add(addrValue)
                    };

                    for (Address candidate : candidates) {
                        try {
                            func = getFunctionAt(candidate);
                            if (func != null) {
                                addr = candidate;
                                resolved = true;
                                break;
                            }
                        } catch (Exception e) {
                            // continue
                        }
                    }

                    if (resolved) {
                        sinkAddrToName.put(addr, name);
                        sinkNames.add(name);
                        println("    ✅ Resolved: " + addr + " -> " + name);
                    } else {
                        sinkNames.add(name);
                        println("    ⚠️ Address not resolved, added name only: " + name);
                    }
                } else {
                    sinkNames.add(line);
                    println("    ✅ Added sink name: " + line);
                }
            } catch (Exception e) {
                println("  ⚠️ Failed to parse sink: " + line + " - " + e.getMessage());
            }
        }

        println("  Total sink functions: " + sinkNames.size());
        println("  Sink addresses resolved: " + sinkAddrToName.size());
    }

    private void renameSinkFunctions() {
        for (Map.Entry<Address, String> entry : sinkAddrToName.entrySet()) {
            Address addr = entry.getKey();
            String name = entry.getValue();
            Function f = getFunctionAt(addr);
            if (f != null && !f.getName().equals(name)) {
                println("🔧 Renaming function at " + addr + " to " + name);
                try {
                    f.setName(name, SourceType.USER_DEFINED);
                } catch (DuplicateNameException | InvalidInputException e) {
                    println("⚠️ Rename failed at " + addr + ": " + e.getMessage());
                }
            }
        }
    }

    private Set<Function> findEntryFunctions() {
        Set<Function> result = new HashSet<>();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        for (Address sourceAddr : sourceAddrs) {
            ReferenceIterator refs = refMgr.getReferencesTo(sourceAddr);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (ref.getReferenceType().isCall()) {
                    Address callAddr = ref.getFromAddress();
                    Function callingFunc = getFunctionContaining(callAddr);
                    if (callingFunc != null) {
                        result.add(callingFunc);
                    }
                }
            }
        }
        return result;
    }

    private void analyzeFlowPaths(Set<Function> entryFunctions) {
        for (Function entryFunc : entryFunctions) {
            if (!processedFunctions.contains(entryFunc)) {
                Set<Function> visited = new HashSet<>();
                traceDangerousCalls(entryFunc, 0, new ArrayList<>(), entryFunc, visited);
                processedFunctions.add(entryFunc);
                totalFunctionsAnalyzed++;
            }
        }
    }

    private void traceDangerousCalls(Function currentFunc,
                                     int depth,
                                     List<CallStep> callChain,
                                     Function originFunc,
                                     Set<Function> visited) {
        if (currentFunc == null || depth > MAX_DEPTH || visited.contains(currentFunc)) return;

        visited.add(currentFunc);
        InstructionIterator instIter =
            currentProgram.getListing().getInstructions(currentFunc.getBody(), true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            if (!inst.getFlowType().isCall()) continue;

            for (Reference ref : inst.getReferencesFrom()) {
                if (!ref.getReferenceType().isCall()) continue;

                Function callee = getFunctionAt(ref.getToAddress());
                if (callee == null) continue;

                CallStep step = new CallStep(currentFunc, inst.getAddress(), callee);
                List<CallStep> newChain = new ArrayList<>(callChain);
                newChain.add(step);

                if (sinkNames.contains(callee.getName())) {
                    // 找到危险路径，记录完整调用链中的所有parent→child关系
                    recordDangerousPath(newChain);

                    CallPath path = new CallPath();
                    path.sourceFunction = originFunc;
                    path.sinkFunction = callee;
                    path.sinkCallAddress = inst.getAddress();
                    path.steps = newChain;
                    path.depth = newChain.size();
                    dangerousPaths.computeIfAbsent(originFunc, k -> new ArrayList<>()).add(path);
                    totalPathsFound++;
                } else {
                    traceDangerousCalls(callee, depth + 1, newChain,
                                        originFunc, new HashSet<>(visited));
                }
            }
        }
        visited.remove(currentFunc);
    }

    // 修正：只记录危险路径中的parent→child调用关系
    private void recordDangerousPath(List<CallStep> pathSteps) {
        for (CallStep step : pathSteps) {
            parentChildAddrs
                .computeIfAbsent(step.caller, k -> new LinkedHashMap<>())
                .computeIfAbsent(step.callee, k -> new LinkedHashSet<>())
                .add(step.callAddr);
        }
    }

    // 唯一调用统计
    private void analyzeUniqueCallStatistics() {
        println("\n📊 Analyzing unique call statistics...");

        uniqueCallRecords.clear();
        parentFunctionCallCount.clear();
        parentToChildren.clear();
        functionFrequency.clear();
        allFunctionsInChains.clear();
        uniqueCallSites.clear();

        for (List<CallPath> paths : dangerousPaths.values()) {
            for (CallPath path : paths) {
                int pathLength = path.steps.size();
                pathLengthDistribution.put(pathLength,
                    pathLengthDistribution.getOrDefault(pathLength, 0) + 1);

                for (CallStep step : path.steps) {
                    Function caller = step.caller;
                    Function callee = step.callee;
                    Address callAddr = step.callAddr;

                    String uniqueCallKey =
                        caller.getName() + "@" + callAddr.toString() + "->" + callee.getName();

                    if (!uniqueCallRecords.contains(uniqueCallKey)) {
                        uniqueCallRecords.add(uniqueCallKey);

                        parentFunctionCallCount.put(caller,
                            parentFunctionCallCount.getOrDefault(caller, 0) + 1);
                        parentToChildren.computeIfAbsent(caller, k -> new HashSet<>()).add(callee);

                        functionFrequency.put(caller,
                            functionFrequency.getOrDefault(caller, 0) + 1);
                        functionFrequency.put(callee,
                            functionFrequency.getOrDefault(callee, 0) + 1);

                        uniqueCallSites.put(uniqueCallKey,
                            new CallSiteInfo(caller, callAddr, callee));
                    } else {
                        CallSiteInfo siteInfo = uniqueCallSites.get(uniqueCallKey);
                        if (siteInfo != null) {
                            siteInfo.pathCount++;
                        }
                    }

                    allFunctionsInChains.add(caller);
                    allFunctionsInChains.add(callee);
                }
            }
        }

        println("  Unique call statistics analysis completed.");
        println("  Total unique functions in chains: " + allFunctionsInChains.size());
        println("  Total unique call records: " + uniqueCallRecords.size());
        println("  Total unique parent functions: " + parentFunctionCallCount.size());
    }

    private void exportUniqueCallStatistics(String outputPath) {
        println("\n📈 Exporting unique call statistics to: " + outputPath);

        int totalUniqueFunctionOccurrences = 0;
        for (Integer count : functionFrequency.values()) {
            totalUniqueFunctionOccurrences += count;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("=== UNIQUE FUNCTION CALL CHAIN STATISTICS ===\n\n");

            writer.write("1. BASIC STATISTICS (Based on Unique Call Sites)\n");
            writer.write("===============================================\n");
            writer.write("Total dangerous paths found: " + totalPathsFound + "\n");
            writer.write("Total functions analyzed: " + totalFunctionsAnalyzed + "\n");
            writer.write("Total unique functions in chains: " + allFunctionsInChains.size() + "\n");
            writer.write("Total unique call records: " + uniqueCallRecords.size() + "\n");
            writer.write("Total unique function occurrences: " +
                         totalUniqueFunctionOccurrences + "\n");
            writer.write("Total unique parent functions: " +
                         parentFunctionCallCount.size() + "\n");
            writer.write("Average unique calls per path: " +
                         String.format("%.2f",
                             (double) uniqueCallRecords.size() /
                             Math.max(1, totalPathsFound)) +
                         "\n\n");

            writer.write("2. PATH LENGTH DISTRIBUTION\n");
            writer.write("==========================\n");
            for (Map.Entry<Integer, Integer> entry : pathLengthDistribution.entrySet()) {
                int pathLength = entry.getKey();
                int pathCount = entry.getValue();
                writer.write("Length " + pathLength + ": " + pathCount + " paths\n");
            }
            writer.write("\n");

            writer.write("3. PARENT FUNCTION UNIQUE CALL STATISTICS " +
                         "(sorted by unique call count)\n");
            writer.write("======================================================================\n");
            List<Map.Entry<Function, Integer>> sortedParents =
                new ArrayList<>(parentFunctionCallCount.entrySet());
            sortedParents.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            int totalUniqueChildren = 0;

            for (Map.Entry<Function, Integer> entry : sortedParents) {
                Function parent = entry.getKey();

                Set<Function> children = parentToChildren.get(parent);
                int childCount = (children == null ? 0 : children.size());

                totalUniqueChildren += childCount;

                int uniqueCallCount = entry.getValue();
                int totalOccurrences = functionFrequency.get(parent);

                writer.write(String.format(
                    "%-40s | Unique Calls: %3d | Total Occurrences: %3d | " +
                    "Unique Children: %3d | Address: %s\n",
                    parent.getName(), uniqueCallCount, totalOccurrences,
                    childCount, parent.getEntryPoint()
                ));
            }

            writer.write(String.format("Total Unique Children " +
                                       "(summed across all parents): %d\n",
                                       totalUniqueChildren));

            writer.write("\n");

            writer.write("4. FUNCTION UNIQUE OCCURRENCES IN ALL CHAINS " +
                         "(sorted by unique occurrences)\n");
            writer.write("===========================================================================\n");
            List<Map.Entry<Function, Integer>> sortedFrequency =
                new ArrayList<>(functionFrequency.entrySet());
            sortedFrequency.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            for (Map.Entry<Function, Integer> entry : sortedFrequency) {
                Function func = entry.getKey();
                int uniqueOccurrences = entry.getValue();
                Integer asParentCount = parentFunctionCallCount.get(func);
                String parentInfo = asParentCount != null
                    ? " (As parent: " + asParentCount + " unique calls)"
                    : " (Never as parent)";
                writer.write(String.format(
                    "%-40s | Unique Occurrences: %3d%s | Address: %s\n",
                    func.getName(), uniqueOccurrences, parentInfo,
                    func.getEntryPoint()
                ));
            }
            writer.write("\n");

            writer.write("5. DETAILED UNIQUE PARENT-CHILD RELATIONSHIPS\n");
            writer.write("============================================\n");
            for (Map.Entry<Function, Set<Function>> entry : parentToChildren.entrySet()) {
                Function parent = entry.getKey();
                Set<Function> children = entry.getValue();
                int parentUniqueCallCount = parentFunctionCallCount.get(parent);
                int parentUniqueOccurrences = functionFrequency.get(parent);
                writer.write("Parent: " + parent.getName() + " (" +
                             parent.getEntryPoint() + ")\n");
                writer.write("  Unique calls as parent: " + parentUniqueCallCount +
                             ", Unique total occurrences: " +
                             parentUniqueOccurrences + "\n");
                writer.write("  Unique Children (" +
                             (children == null ? 0 : children.size()) + "):\n");
                if (children != null) {
                    for (Function child : children) {
                        int childUniqueOccurrences = functionFrequency.get(child);
                        writer.write("    - " + child.getName() +
                                     " (Unique occurrences: " +
                                     childUniqueOccurrences + ") (" +
                                     child.getEntryPoint() + ")\n");
                    }
                }
                writer.write("\n");
            }

            writer.write("6. TOP 10 UNIQUE STATISTICS\n");
            writer.write("===========================\n");

            writer.write("Top 10 Most Active Parent Functions " +
                         "(by unique calls as parent):\n");
            List<Map.Entry<Function, Integer>> top10Parents = new ArrayList<>();
            for (int i = 0; i < Math.min(10, sortedParents.size()); i++) {
                top10Parents.add(sortedParents.get(i));
            }
            for (Map.Entry<Function, Integer> entry : top10Parents) {
                writer.write("  " + entry.getKey().getName() + ": " +
                             entry.getValue() + " unique calls as parent\n");
            }
            writer.write("\n");

            writer.write("Top 10 Most Frequent Functions " +
                         "(by unique occurrences):\n");
            List<Map.Entry<Function, Integer>> top10Frequent = new ArrayList<>();
            for (int i = 0; i < Math.min(10, sortedFrequency.size()); i++) {
                top10Frequent.add(sortedFrequency.get(i));
            }
            for (Map.Entry<Function, Integer> entry : top10Frequent) {
                writer.write("  " + entry.getKey().getName() + ": appears " +
                             entry.getValue() + " times uniquely\n");
            }
            writer.write("\n");

            writer.write("Functions with Most Unique Children:\n");
            List<Map.Entry<Function, Set<Function>>> sortedByChildren =
                new ArrayList<>(parentToChildren.entrySet());
            sortedByChildren.sort(
                new Comparator<Map.Entry<Function, Set<Function>>>() {
                    @Override
                    public int compare(Map.Entry<Function, Set<Function>> a,
                                       Map.Entry<Function, Set<Function>> b) {
                        int asz = a.getValue() == null ? 0 : a.getValue().size();
                        int bsz = b.getValue() == null ? 0 : b.getValue().size();
                        return Integer.compare(bsz, asz);
                    }
                });
            List<Map.Entry<Function, Set<Function>>> top10Children = new ArrayList<>();
            for (int i = 0; i < Math.min(10, sortedByChildren.size()); i++) {
                top10Children.add(sortedByChildren.get(i));
            }
            for (Map.Entry<Function, Set<Function>> entry : top10Children) {
                int cnt = entry.getValue() == null ? 0 : entry.getValue().size();
                writer.write("  " + entry.getKey().getName() + ": " +
                             cnt + " unique children\n");
            }

        } catch (IOException e) {
            printerr("❌ Failed to write unique call statistics to file: " +
                     e.getMessage());
        }
    }

    private void exportUniqueCallSites(String outputPath) {
        println("\n📍 Exporting unique call sites to CSV: " + outputPath);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("CallSiteID,CallerFunction,CallerAddress,CallAddress," +
                         "CalleeFunction,CalleeAddress,PathCount\n");

            int callSiteId = 1;
            List<Map.Entry<String, CallSiteInfo>> sortedCallSites =
                new ArrayList<>(uniqueCallSites.entrySet());
            sortedCallSites.sort(
                (a, b) -> Integer.compare(b.getValue().pathCount,
                                          a.getValue().pathCount));

            for (Map.Entry<String, CallSiteInfo> entry : sortedCallSites) {
                CallSiteInfo siteInfo = entry.getValue();

                writer.write(String.format("%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d\n",
                    callSiteId,
                    siteInfo.caller.getName(),
                    siteInfo.caller.getEntryPoint().toString(),
                    siteInfo.callAddr.toString(),
                    siteInfo.callee.getName(),
                    siteInfo.callee.getEntryPoint().toString(),
                    siteInfo.pathCount
                ));
                callSiteId++;
            }

        } catch (IOException e) {
            printerr("❌ Failed to write unique call sites to CSV: " +
                     e.getMessage());
        }
    }

    private void exportDetailedPathsAndFunctions(String outputPath) {
        println("\n📋 Exporting detailed paths and functions to: " + outputPath);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("=== DETAILED PATHS AND FUNCTIONS ANALYSIS " +
                         "(UNIQUE CALL BASED) ===\n\n");

            writer.write("1. ALL DANGEROUS PATHS (Total: " + totalPathsFound + ")\n");
            writer.write("===============================================\n");

            int pathIndex = 1;
            for (Map.Entry<Function, List<CallPath>> entry :
                     dangerousPaths.entrySet()) {
                Function sourceFunc = entry.getKey();
                List<CallPath> paths = entry.getValue();

                writer.write("\nSource Function: " + sourceFunc.getName() +
                             " (" + sourceFunc.getEntryPoint() + ")\n");
                writer.write("Paths from this source: " + paths.size() + "\n");
                writer.write("----------------------------------------\n");

                for (CallPath path : paths) {
                    writer.write("Path #" + pathIndex +
                                 " (Length: " + path.steps.size() + ")\n");
                    writer.write("  Source: " +
                                 path.sourceFunction.getName() + " -> Sink: " +
                                 path.sinkFunction.getName() + "\n");
                    writer.write("  Sink Call Address: " +
                                 path.sinkCallAddress + "\n");
                    writer.write("  Call Chain:\n");

                    for (int i = 0; i < path.steps.size(); i++) {
                        CallStep step = path.steps.get(i);
                        writer.write("    " + (i + 1) + ". " +
                                     step.caller.getName() +
                                     " (" + step.caller.getEntryPoint() + ") -> " +
                                     step.callee.getName() +
                                     " (" + step.callee.getEntryPoint() + ")\n");
                        writer.write("       Call Address: " +
                                     step.callAddr + "\n");
                    }
                    writer.write("\n");
                    pathIndex++;
                }
            }

            writer.write("\n2. ANALYZED ENTRY FUNCTIONS (Total: " +
                         totalFunctionsAnalyzed + ")\n");
            writer.write("==================================================\n");
            int funcIndex = 1;
            for (Function func : processedFunctions) {
                List<CallPath> pathsFromFunc = dangerousPaths.get(func);
                int pathCount = pathsFromFunc != null ? pathsFromFunc.size() : 0;
                writer.write(funcIndex + ". " + func.getName() + " (" +
                             func.getEntryPoint() + ") - Generated " +
                             pathCount + " dangerous paths\n");
                funcIndex++;
            }

            writer.write("\n3. ALL UNIQUE FUNCTIONS IN CHAINS (Total: " +
                         allFunctionsInChains.size() + ")\n");
            writer.write("================================================================\n");
            List<Function> sortedUniqueFunctions =
                new ArrayList<>(allFunctionsInChains);
            sortedUniqueFunctions.sort(
                (a, b) -> a.getName().compareTo(b.getName()));

            funcIndex = 1;
            for (Function func : sortedUniqueFunctions) {
                int uniqueOccurrences = functionFrequency.getOrDefault(func, 0);
                Integer asParentCount = parentFunctionCallCount.get(func);
                Set<Function> children = parentToChildren.get(func);

                writer.write(funcIndex + ". " + func.getName() + " (" +
                             func.getEntryPoint() + ")\n");
                writer.write("   Unique Occurrences: " +
                             uniqueOccurrences + "\n");
                writer.write("   As Parent: " +
                             (asParentCount != null
                                 ? asParentCount + " unique calls"
                                 : "Never") + "\n");
                writer.write("   Unique Children Count: " +
                             (children != null ? children.size() : 0) + "\n");

                if (children != null && !children.isEmpty()) {
                    writer.write("   Children: ");
                    List<String> childNames = new ArrayList<>();
                    for (Function child : children) {
                        childNames.add(child.getName());
                    }
                    writer.write(String.join(", ", childNames) + "\n");
                }
                writer.write("\n");
                funcIndex++;
            }

            writer.write("\n4. ALL UNIQUE CALL RECORDS (Total: " +
                         uniqueCallRecords.size() + ")\n");
            writer.write("=======================================================\n");
            List<String> sortedCallRecords =
                new ArrayList<>(uniqueCallRecords);
            Collections.sort(sortedCallRecords);

            int callIndex = 1;
            for (String callRecord : sortedCallRecords) {
                CallSiteInfo siteInfo = uniqueCallSites.get(callRecord);
                writer.write(callIndex + ". " + callRecord);
                if (siteInfo != null) {
                    writer.write(" (Paths through this call: " +
                                 siteInfo.pathCount + ")");
                }
                writer.write("\n");
                callIndex++;
            }

        } catch (IOException e) {
            printerr("❌ Failed to write detailed analysis to file: " +
                     e.getMessage());
        }
    }

    private void exportPathsToCSV(String outputPath) {
        println("\n📊 Exporting paths data to CSV: " + outputPath);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("PathID,SourceFunction,SourceAddress,SinkFunction," +
                         "SinkAddress,SinkCallAddress,PathLength,CallChain\n");

            int pathId = 1;
            for (Map.Entry<Function, List<CallPath>> entry :
                     dangerousPaths.entrySet()) {
                List<CallPath> paths = entry.getValue();

                for (CallPath path : paths) {
                    StringBuilder callChain = new StringBuilder();
                    for (int i = 0; i < path.steps.size(); i++) {
                        CallStep step = path.steps.get(i);
                        if (i > 0) callChain.append(" -> ");
                        callChain.append(step.caller.getName());
                        if (i == path.steps.size() - 1) {
                            callChain.append(" -> ")
                                     .append(step.callee.getName());
                        }
                    }

                    writer.write(String.format(
                        "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\"\n",
                        pathId,
                        path.sourceFunction.getName(),
                        path.sourceFunction.getEntryPoint().toString(),
                        path.sinkFunction.getName(),
                        path.sinkFunction.getEntryPoint().toString(),
                        path.sinkCallAddress.toString(),
                        path.steps.size(),
                        callChain.toString()
                    ));
                    pathId++;
                }
            }

        } catch (IOException e) {
            printerr("❌ Failed to write CSV data to file: " + e.getMessage());
        }
    }

    private void exportDangerousCallerCalleeChains(String outputPath) {
        println("📦 Exporting SINK-related caller-callee chains and decompiled caller code...");

        Set<String> seenPairs = new HashSet<>();
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.setOptions(new DecompileOptions());
        decompInterface.setSimplificationStyle("decompile");
        if (!decompInterface.openProgram(currentProgram)) {
            println("❌ Failed to initialize decompiler.");
            return;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            for (List<CallPath> paths : dangerousPaths.values()) {
                for (CallPath path : paths) {
                    for (CallStep step : path.steps) {
                        String pairKey = step.caller.getEntryPoint().toString() +
                                         "->" + step.callee.getEntryPoint().toString();
                        if (seenPairs.contains(pairKey)) continue;
                        seenPairs.add(pairKey);

                        DecompileResults results =
                            decompInterface.decompileFunction(step.caller, 60, monitor);
                        if (!results.decompileCompleted()) continue;

                        String decompiledCode = results.getDecompiledFunction().getC();
                        String correctedCode =
                            replaceFunctionHeaderName(decompiledCode,
                                                      step.caller.getName());
                        String numberedCode = addLineNumbers(correctedCode);

                        writer.write("---------------------\n");
                        writer.write(step.caller.getName() + " call " +
                                     step.callee.getName() + "\n");
                        writer.write("++++++++\n");
                        writer.write(numberedCode);
                        writer.write("\n");
                    }
                }
            }
        } catch (IOException e) {
            printerr("❌ Failed to write sink chain to file: " + e.getMessage());
        }
    }

    private String replaceFunctionHeaderName(String cCode, String realName) {
        String[] lines = cCode.split("\n");
        StringBuilder out = new StringBuilder();
        boolean replaced = false;

        for (String line : lines) {
            if (!replaced &&
                line.matches("^\\s*\\w[\\w\\s\\*]+\\s+FUN_[0-9a-fA-Fx]+\\s*\\(.*\\).*")) {
                line = line.replaceFirst("FUN_[0-9a-fA-Fx]+", realName);
                replaced = true;
            }
            out.append(line).append("\n");
        }
        return out.toString();
    }

    private void printStatistics() {
        println("\n📊 Statistics:");
        println("  Total Functions Analyzed: " + totalFunctionsAnalyzed);
        println("  Total Dangerous Paths: " + totalPathsFound);
        println("  Functions with Dangerous Paths: " + dangerousPaths.size());

        println("\n📊 Unique Function Chain Statistics:");
        println("  Total Unique Functions in Chains: " +
                allFunctionsInChains.size());
        println("  Total Unique Call Records: " +
                uniqueCallRecords.size());
        println("  Total Unique Function Occurrences: " +
                getTotalUniqueFunctionOccurrences());
        println("  Total Unique Parent Functions: " +
                parentFunctionCallCount.size());
        println("  Average Unique Calls per Path: " +
                String.format("%.2f",
                    (double) uniqueCallRecords.size() /
                    Math.max(1, totalPathsFound)));
        double totalWeightedLength = 0;
        for (Map.Entry<Integer, Integer> entry :
                 pathLengthDistribution.entrySet()) {
            totalWeightedLength += entry.getKey() * entry.getValue();
        }
        double averagePathLength = totalPathsFound == 0
            ? 0.0
            : totalWeightedLength / totalPathsFound;
        println("  Average Path Length: " +
                String.format("%.2f", averagePathLength));

        if (!parentFunctionCallCount.isEmpty()) {
            Function mostActiveParent = parentFunctionCallCount.entrySet()
                .stream()
                .max(Map.Entry.comparingByValue())
                .get().getKey();
            int maxCalls = parentFunctionCallCount.get(mostActiveParent);
            println("  Most Active Parent Function: " +
                    mostActiveParent.getName() + " (" +
                    maxCalls + " unique calls)");
        }

        println("  Path Length Distribution:");
        List<Map.Entry<Integer, Integer>> sortedPathLengths =
            new ArrayList<>(pathLengthDistribution.entrySet());
        sortedPathLengths.sort(
            new Comparator<Map.Entry<Integer, Integer>>() {
                @Override
                public int compare(Map.Entry<Integer, Integer> a,
                                   Map.Entry<Integer, Integer> b) {
                    return a.getKey().compareTo(b.getKey());
                }
            });
        for (Map.Entry<Integer, Integer> entry : sortedPathLengths) {
            println("    Length " + entry.getKey() + ": " +
                    entry.getValue() + " paths");
        }

        int linkParents = parentChildAddrs.size();
        int linkEdges = 0;
        int linkSites = 0;
        for (Map<Function, Set<Address>> m : parentChildAddrs.values()) {
            linkEdges += m.size();
            for (Set<Address> s : m.values()) linkSites += s.size();
        }
        println("\n🔗 Dangerous Path Parent→Child Call Map:");
        println("  Parents in danger paths: " + linkParents +
                ", Parent→Child Edges: " + linkEdges +
                ", Call Sites: " + linkSites);
    }

    private int getTotalUniqueFunctionOccurrences() {
        int total = 0;
        for (Integer count : functionFrequency.values()) {
            total += count;
        }
        return total;
    }

    private String addLineNumbers(String decompiledCode) {
        StringBuilder numberedCode = new StringBuilder();
        String[] lines = decompiledCode.split("\n");
        int maxLineNumber = lines.length;
        int lineNumberWidth = String.valueOf(maxLineNumber).length();

        for (int i = 0; i < lines.length; i++) {
            int lineNumber = i + 1;
            String formattedLineNumber =
                String.format("%" + lineNumberWidth + "d", lineNumber);
            numberedCode.append(formattedLineNumber)
                        .append(": ")
                        .append(lines[i])
                        .append("\n");
        }

        return numberedCode.toString();
    }

    private Set<String> buildExcludedEPsByGlobalShare(double cutoff) {
        int total = 0;
        Map<String, Integer> occByEP = new HashMap<>();
        for (Map.Entry<Function, Integer> e : functionFrequency.entrySet()) {
            Function f = e.getKey();
            int cnt = e.getValue();
            total += cnt;
            String ep = f.getEntryPoint().toString();
            occByEP.put(ep, occByEP.getOrDefault(ep, 0) + cnt);
        }
        Set<String> excluded = new HashSet<>();
        if (total <= 0) return excluded;

        for (Map.Entry<String, Integer> e : occByEP.entrySet()) {
            double share =
                (double) e.getValue() / (double) total;
            if (share >= cutoff) {
                excluded.add(e.getKey());
            }
        }

        println(String.format("🧮 Global-share base: total=%d, " +
                              "excluded=%d (≥ %.0f%%)",
                              total, excluded.size(), cutoff * 100));
        return excluded;
    }

    private Set<String> buildExcludedEPsByParentShare(double cutoff) {
        Map<String, Integer> occByEP = new HashMap<>();
        int totalParentsOcc = 0;

        for (Function parent : parentToChildren.keySet()) {
            String ep = parent.getEntryPoint().toString();
            int cnt = functionFrequency.getOrDefault(parent, 0);
            totalParentsOcc += cnt;
            occByEP.put(ep, occByEP.getOrDefault(ep, 0) + cnt);
        }

        Set<String> excluded = new HashSet<>();
        if (totalParentsOcc <= 0) return excluded;

        for (Map.Entry<String, Integer> e : occByEP.entrySet()) {
            double share =
                (double) e.getValue() / (double) totalParentsOcc;
            if (share >= cutoff) {
                excluded.add(e.getKey());
            }
        }

        println(String.format("🧮 Parent-share base: totalParentsOcc=%d, " +
                              "excluded=%d (≥ %.0f%%)",
                              totalParentsOcc, excluded.size(),
                              cutoff * 100));
        return excluded;
    }

    private void exportParentChildCallsToJSON(String outputPath) {
        println("\n🧩 Exporting Parent→Child calls to JSON (no filtering): " + outputPath);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            JSONArray parentsArr = new JSONArray();

            // 按函数名排序，方便查看
            List<Function> parents = new ArrayList<>(parentChildAddrs.keySet());
            parents.sort(Comparator.comparing(Function::getName));

            for (Function parent : parents) {
                Map<Function, Set<Address>> childMap = parentChildAddrs.get(parent);
                if (childMap == null || childMap.isEmpty()) {
                    continue;
                }

                List<Map.Entry<Function, Set<Address>>> children =
                    new ArrayList<>(childMap.entrySet());
                children.sort(Comparator.comparing(e -> e.getKey().getName()));

                JSONArray childrenArr = new JSONArray();

                for (Map.Entry<Function, Set<Address>> e : children) {
                    Function child = e.getKey();
                    Set<Address> sites = e.getValue();

                    JSONObject childObj = new JSONObject();
                    childObj.put("child_name", child.getName());
                    childObj.put("child_address", child.getEntryPoint().toString());

                    JSONArray sitesArr = new JSONArray();
                    for (Address a : sites) {
                        sitesArr.put(a.toString());
                    }
                    childObj.put("call_sites", sitesArr);
                    childObj.put("call_site_count", sites.size());

                    childrenArr.put(childObj);
                }

                JSONObject parentObj = new JSONObject();
                parentObj.put("parent_name", parent.getName());
                parentObj.put("parent_address", parent.getEntryPoint().toString());
                parentObj.put("children", childrenArr);
                parentObj.put("unique_children_count", childrenArr.length());

                parentsArr.put(parentObj);
            }

            JSONObject root = new JSONObject();
            root.put("program", currentProgram.getName());
            root.put("analysis_scope", "dangerous_paths_only");
            root.put("description",
                    "Parent→Child in dangerous paths; no frequency-based filtering applied.");
            root.put("parent_count", parentsArr.length());
            root.put("data", parentsArr);

            writer.write(root.toString(2));
        } catch (IOException e) {
            printerr("❌ Failed to write parent_child_calls.json: " + e.getMessage());
        }
    }

    private void exportParentChildCallsToCSV(String outputPath) {
        println("\n🧾 Exporting Parent→Child calls to CSV (no filtering): " + outputPath);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("ParentFunction,ParentAddress,ChildFunction,ChildAddress,CallSiteCount,CallSites\n");

            List<Function> parents = new ArrayList<>(parentChildAddrs.keySet());
            parents.sort(Comparator.comparing(Function::getName));

            for (Function parent : parents) {
                String parentEP = parent.getEntryPoint().toString();
                Map<Function, Set<Address>> childMap = parentChildAddrs.get(parent);
                if (childMap == null || childMap.isEmpty()) {
                    continue;
                }

                List<Map.Entry<Function, Set<Address>>> children =
                    new ArrayList<>(childMap.entrySet());
                children.sort(Comparator.comparing(e -> e.getKey().getName()));

                for (Map.Entry<Function, Set<Address>> e : children) {
                    Function child = e.getKey();
                    Set<Address> sites = e.getValue();
                    String childEP = child.getEntryPoint().toString();

                    StringBuilder sitesJoined = new StringBuilder();
                    boolean first = true;
                    for (Address addr : sites) {
                        if (!first) {
                            sitesJoined.append(';');
                        }
                        sitesJoined.append(addr.toString());
                        first = false;
                    }

                    writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\"\n",
                        parent.getName(),
                        parentEP,
                        child.getName(),
                        childEP,
                        sites.size(),
                        sitesJoined.toString()
                    ));
                }
            }

        } catch (IOException e) {
            printerr("❌ Failed to write parent_child_calls.csv: " + e.getMessage());
        }
    }

    private String joinAddresses(Set<Address> addrs, String sep) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Address a : addrs) {
            if (!first) sb.append(sep);
            sb.append(a.toString());
            first = false;
        }
        return sb.toString();
    }
}
