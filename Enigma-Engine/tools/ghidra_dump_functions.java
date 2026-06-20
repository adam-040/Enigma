/* ghidra_dump_functions.java
 * Ghidra headless script: dump function addresses and names as CSV
 * Usage: analyzeHeadless <project> <name> -import <binary>
 *        -postScript ghidra_dump_functions.java
 *        -scriptPath <path-to-this-file>
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.*;

public class ghidra_dump_functions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = System.getProperty("user.dir")
            + File.separator + "ghidra_script_output.tmp";
        
        // Try the tools directory as well
        String altPath = System.getenv("GHIDRA_SCRIPT_OUTPUT");
        if (altPath != null && !altPath.isEmpty()) {
            outputPath = altPath;
        }

        PrintWriter writer = new PrintWriter(outputPath);
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (functions.hasNext()) {
            Function func = functions.next();
            long addr = func.getEntryPoint().getOffset();
            String name = func.getName();
            writer.printf("0x%x,%s%n", addr, name);
            count++;
        }
        writer.close();
        println("Wrote " + count + " functions to " + outputPath);
    }
}
