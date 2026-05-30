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

public class SourceDecompileFunc extends GhidraScript {

    private DecompInterface decompInterface;
    private static String DB_URL = "jdbc:sqlite:/tmp/ghidra_decompile.db";

    @Override
    public void run() throws Exception {
        // Get script arguments
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: -postScript SourceDecompileFuncFromBase64.java <base64_data> <db_path>");
            return;
        }

        String base64Data = args[0];
        DB_URL = "jdbc:sqlite:" + args[1];

        // Create table if not exists
        createTable();

        // Decode the base64 string
        byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
        String decodedStr = new String(decodedBytes, StandardCharsets.UTF_8);
        println("Decoded base64 string: " + decodedStr);

        // Parse the decoded string as JSON array
        JSONArray dataArray = new JSONArray(decodedStr);

        // Initialize decompiler
        decompInterface = getDecompInterface();
        if (decompInterface == null) {
            println("❌ Failed to initialize decompiler interface");
            return;
        }

        // Get current program name
        String programName = currentProgram.getName();
        println("Processing program: " + programName);

        // Process each function
        for (int i = 0; i < dataArray.length(); i++) {
            String funcData = dataArray.getString(i);
            processFunctionData(programName, funcData);
        }

        println("✅ Decompilation completed successfully!");
    }

    private void processFunctionData(String programName, String funcData) {
        try {
            // Parse function name and address
            String[] parts = funcData.split("\\|");
            if (parts.length != 2) {
                println("❌ Invalid function data format: " + funcData);
                return;
            }

            String funcName = parts[0];
            String addrStr = parts[1];

            // Parse address (remove 0x prefix if present)
            if (addrStr.startsWith("0x")) {
                addrStr = addrStr.substring(2);
            }

            Address address;
            try {
                long addrLong = Long.parseLong(addrStr, 16);
                address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrLong);
            } catch (NumberFormatException e) {
                println("❌ Invalid address format: " + addrStr);
                return;
            }

            // Get function at address
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                println("⚠️  No function found at address: " + address);
                // Try to create function at this address
                function = createFunctionAt(address, funcName);
                if (function == null) {
                    println("❌ Failed to create function at address: " + address);
                    return;
                }
            }

            println("Processing function: " + funcName + " at " + address);

            // Decompile the function
            String decompiledCode = decompileFunction(function);
            if (decompiledCode != null && !decompiledCode.isEmpty()) {
                // Insert into database
                insertDecompiledFunction(programName, funcName, address.toString(), decompiledCode);
                println("✅ Successfully processed: " + funcName);
            } else {
                println("❌ Failed to decompile function: " + funcName);
            }

        } catch (Exception e) {
            println("❌ Error processing function data '" + funcData + "': " + e.getMessage());
            e.printStackTrace();
        }
    }

    private Function createFunctionAt(Address address, String funcName) {
        try {
            // Try to create a function at the given address
            Function function = currentProgram.getFunctionManager().createFunction(funcName, address, null, null);
            if (function != null) {
                println("✅ Created function: " + funcName + " at " + address);
            }
            return function;
        } catch (Exception e) {
            println("❌ Failed to create function at " + address + ": " + e.getMessage());
            return null;
        }
    }

    private String decompileFunction(Function function) {
        try {
            DecompileResults results = decompInterface.decompileFunction(function, 30, null);
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            } else {
                println("❌ Decompilation failed for function: " + function.getName());
                return null;
            }
        } catch (Exception e) {
            println("❌ Exception during decompilation: " + e.getMessage());
            return null;
        }
    }

    private DecompInterface getDecompInterface() {
        try {
            DecompInterface decompInterface = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            decompInterface.setOptions(options);
            decompInterface.toggleCCode(true);
            decompInterface.toggleSyntaxTree(true);
            decompInterface.setSimplificationStyle("decompile");

            if (!decompInterface.openProgram(currentProgram)) {
                println("❌ Failed to open program in decompiler");
                return null;
            }

            return decompInterface;
        } catch (Exception e) {
            println("❌ Error initializing decompiler: " + e.getMessage());
            return null;
        }
    }
      
    private Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private void createTable() {
        String sql = "CREATE TABLE IF NOT EXISTS source_decompile (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "file_name TEXT," +
                     "func_name TEXT," +
                     "func_addr TEXT," +
                     "decompiled_code TEXT NOT NULL," +
                     "created_at DATETIME DEFAULT CURRENT_TIMESTAMP," +
                     "UNIQUE(file_name, func_name, func_addr)" +
                     ");";
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            println("✅ Database table created/verified");
        } catch (SQLException e) {
            println("❌ Error creating table: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void insertDecompiledFunction(String fileName, String funcName, String funcAddr, String decompiledCode) {
        String sql = "INSERT OR REPLACE INTO source_decompile(file_name, func_name, func_addr, decompiled_code) VALUES(?, ?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, fileName);
            pstmt.setString(2, funcName);
            pstmt.setString(3, funcAddr);
            pstmt.setString(4, decompiledCode);
            pstmt.executeUpdate();
            println("💾 Saved to database: " + funcName + " at " + funcAddr);
        } catch (SQLException e) {
            println("❌ Error inserting function: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void cleanup(boolean success) {
        if (decompInterface != null) {
            decompInterface.dispose();
        }
        super.cleanup(success);
    }
}