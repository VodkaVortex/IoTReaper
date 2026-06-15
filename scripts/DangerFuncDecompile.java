// @category _iotreaper.tools
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.json.*; // Provided in Ghidra's classpath

public class DangerFuncDecompile extends GhidraScript {

    private static final String INPUT_FILE = "parent_child_calls.json";
    private static final String OUTPUT_FILE = "danger_func_compile.json";

    private DecompInterface decompInterface;

    @Override
    public void run() throws Exception {
        // 1) Find result directory from postScript arguments
        String resultDir = resolveResultDir(getScriptArgs());
        if (resultDir == null) {
            printerr("❌ Could not find a valid result directory containing " + INPUT_FILE);
            return;
        }
        println("▶ Result directory: " + resultDir);

        File inFile = new File(resultDir, INPUT_FILE);
        if (!inFile.isFile()) {
            printerr("❌ Input file not found: " + inFile.getAbsolutePath());
            return;
        }

        // 2) Read input JSON
        JSONObject inRoot;
        try (InputStream is = new FileInputStream(inFile);
             InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            inRoot = new JSONObject(new JSONTokener(isr));
        }

        JSONArray dataArr = inRoot.optJSONArray("data");
        if (dataArr == null) {
            printerr("❌ JSON missing 'data' array: " + inFile.getAbsolutePath());
            return;
        }

        // 3) Init decompiler
        decompInterface = getDecompInterface();

        // 4) Process each parent function
        JSONArray outData = new JSONArray();

        for (int i = 0; i < dataArr.length(); i++) {
            JSONObject item = dataArr.optJSONObject(i);
            if (item == null) continue;

            String parentName = item.optString("parent_name", "");
            String parentAddrStr = item.optString("parent_address", "");
            JSONArray children = item.optJSONArray("children");

            if (parentAddrStr == null || parentAddrStr.isEmpty()) {
                printerr("⚠ Skipping: missing parent_address, parent_name=" + parentName);
                continue;
            }

            Address faddr = safeToAddr(parentAddrStr);
            if (faddr == null) {
                printerr("⚠ Skipping: invalid address " + parentAddrStr + " for parent_name=" + parentName);
                continue;
            }

            Function func = getFunctionAt(faddr);
            if (func == null) {
                func = getFunctionContaining(faddr);
            }
            if (func == null) {
                printerr("⚠ Skipping: no function found at address=" + parentAddrStr + " parent_name=" + parentName);
                continue;
            }

            // Decompile
            String decompiledCode = decompileFunction(func);

            // Add line numbers
            String numberedCode = addLineNumbers(decompiledCode);

            // Extract child names list
            List<String> childNames = new ArrayList<>();
            if (children != null) {
                for (int j = 0; j < children.length(); j++) {
                    JSONObject ch = children.optJSONObject(j);
                    if (ch != null) {
                        String cn = ch.optString("child_name", "");
                        if (!cn.isEmpty()) childNames.add(cn);
                    }
                }
            }

            // Build output object
            JSONObject outItem = new JSONObject();
            outItem.put("parent_name", parentName);
            outItem.put("parent_address", parentAddrStr);
            outItem.put("decompiled_c", numberedCode != null ? numberedCode : JSONObject.NULL);
            outItem.put("children", children != null ? children : new JSONArray());
            outItem.put("child_names", new JSONArray(childNames));

            outData.put(outItem);

            // println(String.format("✓ Done: %s @ %s (%d/%d)", parentName, parentAddrStr, i + 1, dataArr.length()));
            if (monitor.isCancelled()) {
                printerr("⏹ Cancelled by user.");
                break;
            }
        }

        // 5) Save output JSON
        JSONObject outRoot = new JSONObject();
        outRoot.put("program_name", currentProgram != null ? currentProgram.getName() : JSONObject.NULL);
        outRoot.put("timestamp", new Date().toString());
        outRoot.put("data", outData);

        File outFile = new File(resultDir, OUTPUT_FILE);
        try (OutputStream os = new FileOutputStream(outFile);
             OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
            osw.write(outRoot.toString(2));
        }
        println("✅ Output written: " + outFile.getAbsolutePath());
    }

    /**
     * Initialize and return the decompiler interface.
     */
    private DecompInterface getDecompInterface() {
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            throw new RuntimeException("❌ Failed to initialize decompiler: " + ifc.getLastMessage());
        }
        return ifc;
    }

    /**
     * Convert an address string (like "0040c8b0" or "0x0040c8b0") to a Ghidra Address.
     */
    private Address safeToAddr(String addrStr) {
        try {
            String s = addrStr.trim();
            if (!s.startsWith("0x") && !s.startsWith("0X")) {
                s = "0x" + s;
            }
            return toAddr(s);
        } catch (Exception e) {
            printerr("Address conversion failed: " + addrStr + " -> " + e.getMessage());
            return null;
        }
    }

    /**
     * Decompile the given function and return its C code.
     * If decompilation fails, return a comment with the error message.
     */
    private String decompileFunction(Function func) {
        try {
            DecompileResults results = decompInterface.decompileFunction(func, 60, monitor);
            if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
                String msg = (results != null ? results.getErrorMessage() : "unknown");
                return "/* Failed to decompile function: " + func.getName() + " @ " +
                        func.getEntryPoint() + " | " + msg + " */";
            }
            return results.getDecompiledFunction().getC();
        } catch (Exception ex) {
            return "/* Exception during decompile: " + func.getName() + " @ " +
                    func.getEntryPoint() + " | " + ex.getMessage() + " */";
        }
    }

    /**
     * Add line numbers to multi-line code.
     */
    private String addLineNumbers(String code) {
        if (code == null) return null;
        StringBuilder numbered = new StringBuilder();
        String[] lines = code.split("\n", -1); // preserve empty trailing line
        for (int i = 0; i < lines.length; i++) {
            numbered.append(String.format("%4d: %s%n", i + 1, lines[i]));
        }
        return numbered.toString();
    }

    /**
     * Find the result directory from postScript args, by looking for one containing the INPUT_FILE.
     */
    private String resolveResultDir(String[] args) {
        if (args != null) {
            for (String a : args) {
                if (a == null || a.isEmpty()) continue;
                File f = new File(a);
                if (f.isDirectory()) {
                    File probe = new File(f, INPUT_FILE);
                    if (probe.isFile()) {
                        return f.getAbsolutePath();
                    }
                }
            }
        }
        return null;
    }
}
