/// enigma_fks_ingest_from_ghidra.cpp
/// Reads JSON export from Ghidra's EnigmaExportFidMatches script,
/// computes V1+V2 fingerprints from raw bytes, and creates .fkslib files.
///
/// Usage: enigma_fks_ingest_from_ghidra <export.json> <output.fkslib>
///        [--family <name>] [--compiler <name>] [--version <ver>]
///
/// The JSON file is produced by running Ghidra headless with:
///   analyzeHeadless.bat <proj> <name> -import <binary>
///     -postScript EnigmaExportFidMatches.java -scriptPath <path>

#include <ghidra/FksLibrary.h>
#include <ghidra/FunctionFingerprint.h>
#include <ghidra/FNV1a64.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <filesystem>
#include <ctime>
#include <algorithm>

using namespace ghidra;
using json = nlohmann::json;

// ── JSON parsing ─────────────────────────────────────────────────────────────

struct JsonFunction {
    std::string name;
    uint64_t offset = 0;
    int size = 0;
    int instrCount = 0;
    std::string source;
    std::vector<uint8_t> bytes;

    std::string nameDemangled;
    std::string namespacePath;
    bool isThunk = false;
    bool isLibrary = false;
    bool isExported = false;
    bool isExternal = false;
    std::string signature;
    int basicBlocks = 0;
    int cyclomatic = 0;
    int callCount = 0;
    bool hasFrame = false;
    std::vector<uint64_t> calledFunctions;
};

struct JsonExport {
    std::string binary;
    std::vector<JsonFunction> functions;
    int totalFunctions = 0;
    int exportedFunctions = 0;
};

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        char c = hex[i];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F') hi = 10 + c - 'A';
        c = hex[i + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F') lo = 10 + c - 'A';
        bytes.push_back((hi << 4) | lo);
    }
    return bytes;
}

static JsonExport parseJsonExport(const std::string& filePath) {
    JsonExport result;
    std::ifstream in(filePath);
    if (!in.is_open()) {
        std::cerr << "Cannot open JSON file: " << filePath << "\n";
        return result;
    }

    json j;
    try {
        in >> j;
    } catch (const json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
        return result;
    }

    result.binary = j.value("binary", "");
    result.totalFunctions = j.value("total_functions", 0);
    result.exportedFunctions = j.value("exported_functions", 0);

    if (!j.contains("functions") || !j["functions"].is_array()) {
        std::cerr << "No 'functions' array in JSON\n";
        return result;
    }

    for (auto& jf : j["functions"]) {
        JsonFunction f;
        f.name            = jf.value("name", "");
        f.offset          = jf.value("offset", 0ULL);
        f.size            = jf.value("size", 0);
        f.instrCount      = jf.value("instr_count", 0);
        f.source          = jf.value("source", "");
        f.bytes           = hexToBytes(jf.value("bytes", ""));

        f.nameDemangled   = jf.value("name_demangled", "");
        f.namespacePath   = jf.value("namespace", "");
        f.isThunk         = jf.value("is_thunk", false);
        f.isLibrary       = jf.value("is_library", false);
        f.isExported      = jf.value("is_exported", false);
        f.isExternal      = jf.value("is_external", false);
        f.signature       = jf.value("signature", "");
        f.basicBlocks     = jf.value("basic_blocks", 0);
        f.cyclomatic      = jf.value("cyclomatic", 0);
        f.callCount       = jf.value("call_count", 0);
        f.hasFrame        = jf.value("has_frame", false);

        if (jf.contains("called_functions") && jf["called_functions"].is_array()) {
            for (auto& addr : jf["called_functions"]) {
                if (addr.is_number_unsigned()) {
                    f.calledFunctions.push_back(addr.get<uint64_t>());
                }
            }
        }

        result.functions.push_back(std::move(f));
    }

    return result;
}

// ── V1 + V2 hashing from raw bytes (matching FunctionFingerprint.cpp logic) ──

static uint64_t fnv1a64(const uint8_t* data, int length) {
    FNV1a64 h;
    h.update(data, length);
    return h.digest();
}

struct CsInstr {
    std::string mnemonic;
    const uint8_t* bytes;
    int length;
};

static bool isCallOrJump(const std::string& mn) {
    return mn == "call" || mn == "jmp" || mn == "je" || mn == "jne" ||
           mn == "jz" || mn == "jnz" || mn == "jg" || mn == "jge" ||
           mn == "jl" || mn == "jle" || mn == "ja" || mn == "jae" ||
           mn == "jb" || mn == "jbe" || mn == "jo" || mn == "jno" ||
           mn == "js" || mn == "jns" || mn == "jp" || mn == "jnp" ||
           mn == "loop" || mn == "loope" || mn == "loopne";
}

static FunctionFingerprint computeHashes(const uint8_t* bytes, int size, int arch = CS_ARCH_X86) {
    FunctionFingerprint fp;

    // V1: raw-byte FNV-1a
    fp.v1.fullHash  = fnv1a64(bytes, size);                              // all bytes
    int v1ShortLen = std::min(size, FunctionFingerprinter::MAX_SHORT_HASH_BYTES);
    fp.v1.shortHash = fnv1a64(bytes, v1ShortLen);                        // first 32 bytes
    fp.v1.mnemHash  = 0;
    fp.v1.callHash  = 0;

    // V2: Capstone mnemonic-sequence hashing (supports CS_ARCH_X86 and CS_ARCH_ARM64)
    csh handle;
    cs_mode capMode = (arch == CS_ARCH_ARM64) ? CS_MODE_ARM : CS_MODE_64;
    if (cs_open(static_cast<cs_arch>(arch), capMode, &handle) != CS_ERR_OK)
        return fp;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insns = nullptr;
    size_t count = cs_disasm(handle, bytes, size, 0x1000, 32, &insns);

    if (count > 0) {
        std::vector<CsInstr> instrs;
        instrs.reserve(count);
        for (size_t i = 0; i < count; i++) {
            CsInstr ci;
            ci.mnemonic = insns[i].mnemonic;
            ci.bytes = insns[i].bytes;
            ci.length = static_cast<int>(insns[i].size);
            instrs.push_back(ci);
        }

        // V2 fullHash: all mnemonics
        {
            FNV1a64 h;
            for (auto& ci : instrs) {
                h.updateByte(0);
                h.update(reinterpret_cast<const uint8_t*>(ci.mnemonic.data()),
                         static_cast<int>(ci.mnemonic.size()));
            }
            fp.v2.fullHash = h.digest();
        }

        // V2 shortHash: first 8 mnemonics
        {
            FNV1a64 h;
            int n = 0;
            for (auto& ci : instrs) {
                if (n >= 8) break;
                h.updateByte(0);
                h.update(reinterpret_cast<const uint8_t*>(ci.mnemonic.data()),
                         static_cast<int>(ci.mnemonic.size()));
                n++;
            }
            fp.v2.shortHash = h.digest();
        }

        // V2 mnemHash: mnemonics without calls/jumps
        {
            FNV1a64 h;
            for (auto& ci : instrs) {
                if (isCallOrJump(ci.mnemonic)) continue;
                h.updateByte(0);
                h.update(reinterpret_cast<const uint8_t*>(ci.mnemonic.data()),
                         static_cast<int>(ci.mnemonic.size()));
            }
            fp.v2.mnemHash = h.digest();
        }

        // V2 callHash: first 4 bytes of each instruction
        {
            FNV1a64 h;
            for (auto& ci : instrs) {
                int n = std::min(4, ci.length);
                h.update(ci.bytes, n);
            }
            fp.v2.callHash = h.digest();
        }

        cs_free(insns, count);
    }

    cs_close(&handle);
    return fp;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: enigma_fks_ingest_from_ghidra <export.json> <output.fkslib> "
                  << "[--family <name>] [--compiler <name>] [--version <ver>] [--arch x86|arm64]\n";
        return 1;
    }

    std::string jsonPath = argv[1];
    std::string outputPath = argv[2];
    std::string family   = "unknown";
    std::string compiler = "unknown";
    std::string version  = "";
    std::string archStr  = "x86";

    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--family"   && i + 1 < argc) family   = argv[++i];
        else if (arg == "--compiler" && i + 1 < argc) compiler = argv[++i];
        else if (arg == "--version"  && i + 1 < argc) version  = argv[++i];
        else if (arg == "--arch"     && i + 1 < argc) archStr  = argv[++i];
    }

    int capArch = CS_ARCH_X86;
    if (archStr == "arm64" || archStr == "aarch64") capArch = CS_ARCH_ARM64;

    // Parse JSON
    JsonExport data = parseJsonExport(jsonPath);
    if (data.functions.empty()) {
        std::cerr << "No functions found in JSON: " << jsonPath << "\n";
        return 1;
    }

    // If binary name was in JSON, use it for family
    if (family == "unknown" && !data.binary.empty()) {
        family = data.binary;
        auto dot = family.rfind('.');
        if (dot != std::string::npos) family = family.substr(0, dot);
    }

    // ── Build address → index mapping for relation resolution ──
    std::unordered_map<uint64_t, int> addrToIndex;
    for (int i = 0; i < static_cast<int>(data.functions.size()); i++) {
        addrToIndex[data.functions[i].offset] = i;
    }

    // ── Build FksLibrary ──
    FksLibrary lib;
    FksLibraryMeta meta;
    meta.family      = family;
    meta.version     = version;
    meta.compiler    = compiler;
    meta.language    = (capArch == CS_ARCH_ARM64) ? "AARCH64:LE:64:v8A" : "x86:LE:64:default";
    meta.description = "Imported from Ghidra FID analysis of " + data.binary;
    meta.created     = static_cast<uint64_t>(std::time(nullptr));
    lib.setMeta(meta);

    int totalIngested = 0;
    int skipped = 0;

    for (auto& func : data.functions) {
        if (func.bytes.empty() || func.bytes.size() < 1) {
            skipped++;
            continue;
        }

        FunctionFingerprint fp = computeHashes(func.bytes.data(),
                                                static_cast<int>(func.bytes.size()),
                                                capArch);

        FksFunction fkFunc;
        fkFunc.uid             = fp.fullHash();
        fkFunc.name            = func.name;
        fkFunc.nameDemangled   = func.nameDemangled;
        fkFunc.namespacePath   = func.namespacePath;
        fkFunc.hashes.fullHash  = fp.v1.fullHash;
        fkFunc.hashes.shortHash = fp.v1.shortHash;
        fkFunc.hashes.mnemHash  = fp.v1.mnemHash;
        fkFunc.hashes.callHash  = fp.v1.callHash;
        fkFunc.hashesV2.fullHash  = fp.v2.fullHash;
        fkFunc.hashesV2.shortHash = fp.v2.shortHash;
        fkFunc.hashesV2.mnemHash  = fp.v2.mnemHash;
        fkFunc.hashesV2.callHash  = fp.v2.callHash;
        fkFunc.bodySize    = static_cast<uint32_t>(func.bytes.size());
        fkFunc.instrCount  = static_cast<uint16_t>(func.instrCount);
        fkFunc.callCount   = static_cast<uint16_t>(func.callCount);
        fkFunc.basicBlocks = static_cast<uint16_t>(func.basicBlocks);
        fkFunc.cyclomatic  = static_cast<uint16_t>(func.cyclomatic);
        fkFunc.hasFrame    = func.hasFrame;
        fkFunc.isThunk     = func.isThunk;
        fkFunc.isLibrary   = func.isLibrary;
        fkFunc.isExternal  = func.isExternal;
        fkFunc.signature   = func.signature;
        fkFunc.exported    = func.isExported;
        fkFunc.virtualAddress = func.offset;

        lib.addFunction(fkFunc);
        totalIngested++;
    }

    // ── Populate FksRelation table from caller→callee data ──
    // Track which JSON indices were actually ingested into the library
    std::unordered_map<int, int> jsonIdxToLibIdx;  // json index → library index
    int libIdx = 0;
    for (int jsonIdx = 0; jsonIdx < static_cast<int>(data.functions.size()); jsonIdx++) {
        auto& func = data.functions[jsonIdx];
        if (func.bytes.empty() || func.bytes.size() < 1) continue;
        jsonIdxToLibIdx[jsonIdx] = libIdx++;
    }

    for (int callerIdx = 0; callerIdx < static_cast<int>(data.functions.size()); callerIdx++) {
        auto& func = data.functions[callerIdx];
        auto callerIt = jsonIdxToLibIdx.find(callerIdx);
        if (callerIt == jsonIdxToLibIdx.end()) continue;  // caller was skipped

        for (uint64_t calleeAddr : func.calledFunctions) {
            auto it = addrToIndex.find(calleeAddr);
            if (it == addrToIndex.end()) continue;  // callee not found

            auto calleeIt = jsonIdxToLibIdx.find(it->second);
            if (calleeIt == jsonIdxToLibIdx.end()) continue;  // callee was skipped

            if (callerIt->second == calleeIt->second) continue;  // self-loop

            FksRelation rel;
            rel.callerIndex = static_cast<uint32_t>(callerIt->second);
            rel.calleeIndex = static_cast<uint32_t>(calleeIt->second);
            lib.addRelation(rel);
        }
    }

    // Save
    if (!lib.saveToFile(outputPath)) {
        std::cerr << "Failed to save: " << outputPath << "\n";
        return 1;
    }

    std::cerr << "Ghidra FKS Ingest: " << data.binary << "\n";
    std::cerr << "  Functions in JSON: " << data.functions.size() << "\n";
    std::cerr << "  Ingested:          " << totalIngested << "\n";
    std::cerr << "  Skipped:           " << skipped << "\n";
    std::cerr << "  Relations:         " << lib.getRelations().size() << "\n";
    std::cerr << "  Output:            " << outputPath << "\n";

    return 0;
}
