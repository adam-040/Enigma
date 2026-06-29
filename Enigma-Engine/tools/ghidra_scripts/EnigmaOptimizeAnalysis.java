/* ###
 * IP: GHIDRA
 *
 * EnigmaOptimizeAnalysis.java
 *
 * Disables ONLY the slowest non-essential Ghidra analyzers for PE files.
 * These provide no value to FKS fingerprint extraction:
 *  - WindowsResourceReference: slow on large PE files (90s for mshtml)
 *  - ASCII Strings: not needed (we don't export strings)
 *  - Embedded Media: not needed
 *  - Function ID: redundant (we ARE the FID system)
 *  - PDB Universal: not needed (we don't use PDB)
 *  - Demangler Microsoft: we do our own demangling
 *  - Windows x86 PE RTTI Analyzer: RTTI not used by FKS
 *
 * Does NOT disable: Stack, Data Reference, Scalar (needed by decompiler),
 *   Constant Reference (needed by decompiler), Create Address Tables,
 *   Disassemble Entry Points (critical!), Create Function (critical!).
 */
import ghidra.app.script.GhidraScript;

public class EnigmaOptimizeAnalysis extends GhidraScript {

    private static final String[] DISABLE = {
        "ASCII Strings",
        "Embedded Media",
        "Function ID",
        "PDB Universal",
        "Demangler Microsoft",
        "Windows x86 PE RTTI Analyzer",
        "WindowsResourceReference",
    };

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) return;

        int disabled = 0;
        for (String name : DISABLE) {
            try {
                setAnalysisOption(currentProgram, name, "false");
                disabled++;
            } catch (Exception e) {
                // analyzer may not exist in this version
            }
        }
        println("  [Opt] Disabled " + disabled + " analyzers");
    }
}
