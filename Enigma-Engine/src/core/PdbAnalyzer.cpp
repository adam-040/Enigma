#include <ghidra/PdbAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Msg.h>
#include <cstdint>
#include <string>
#include <fstream>
#include <vector>
#include <algorithm>

namespace ghidra {

namespace {

// RSDS signature for CodeView PDB 7.0
static const uint8_t RSDS_SIG[4] = {'R', 'S', 'D', 'S'};
// NB10 signature for CodeView PDB 2.0
static const uint8_t NB10_SIG[4] = {'N', 'B', '1', '0'};

struct PdbInfo {
    std::string pdbPath;
    bool valid = false;
};

static PdbInfo findPdbInfo(Program* program) {
    PdbInfo info;
    Memory* memory = program->getMemory();
    if (!memory) return info;

    for (auto* block : memory->getBlocks()) {
        std::string name = block->getName();
        if (name != ".rdata" && name.find("rdata") == std::string::npos &&
            name != ".data" && name != "DATA" && name.find("debug") == std::string::npos) {
            continue;
        }

        Address start = block->getStart();
        Address end = block->getEnd();
        int64_t size = end.getOffset() - start.getOffset() + 1;
        if (size > 1024 * 1024) size = 1024 * 1024;

        std::vector<uint8_t> buf(static_cast<size_t>(size));
        int read = block->getBytes(start, buf.data(), static_cast<int>(size));
        if (read <= 0) continue;

        // Search for RSDS signature
        for (int64_t i = 0; i < static_cast<int64_t>(size) - 24; ++i) {
            bool isRSDS = true;
            for (int j = 0; j < 4; ++j) {
                if (buf[static_cast<size_t>(i + j)] != RSDS_SIG[j]) {
                    isRSDS = false; break;
                }
            }
            if (isRSDS) {
                // RSDS format: sig(4) + guid(16) + age(4) + pdbPath(null-terminated)
                size_t pathOff = static_cast<size_t>(i) + 24;
                if (pathOff < buf.size()) {
                    const char* pathStr = reinterpret_cast<const char*>(buf.data() + pathOff);
                    // Find null terminator
                    size_t pathLen = 0;
                    while (pathOff + pathLen < buf.size() && pathStr[pathLen] != 0) ++pathLen;
                    if (pathLen > 0 && pathLen < 512) {
                        info.pdbPath = std::string(pathStr, pathLen);
                        // Normalize path separators
                        std::replace(info.pdbPath.begin(), info.pdbPath.end(), '\\', '/');
                        info.valid = true;
                        return info;
                    }
                }
            }

            // Search for NB10 signature (older format)
            bool isNB10 = true;
            for (int j = 0; j < 4; ++j) {
                if (buf[static_cast<size_t>(i + j)] != NB10_SIG[j]) {
                    isNB10 = false; break;
                }
            }
            if (isNB10) {
                // NB10 format: sig(4) + offset(4) + sig2(4) + age(4) + pdbPath(null-terminated)
                size_t pathOff = static_cast<size_t>(i) + 16;
                if (pathOff < buf.size()) {
                    const char* pathStr = reinterpret_cast<const char*>(buf.data() + pathOff);
                    size_t pathLen = 0;
                    while (pathOff + pathLen < buf.size() && pathStr[pathLen] != 0) ++pathLen;
                    if (pathLen > 0 && pathLen < 512) {
                        info.pdbPath = std::string(pathStr, pathLen);
                        std::replace(info.pdbPath.begin(), info.pdbPath.end(), '\\', '/');
                        info.valid = true;
                        return info;
                    }
                }
            }
        }
    }
    return info;
}

} // anonymous namespace

PdbAnalyzer::PdbAnalyzer()
    : AbstractAnalyzer("PDB MSDIA",
                       "Loads PDB debug information using MSDIA COM interface.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool PdbAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

bool PdbAnalyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Scanning for PDB debug information...");

    PdbInfo info = findPdbInfo(program);
    if (info.valid) {
        Msg::info(getName(), "Found PDB reference: " + info.pdbPath);
        program->getBookmarkManager()->setBookmark(
            program->getMinAddress(), "INFO",
            "PDB file: " + info.pdbPath);
    }

    return true;
}

} // namespace ghidra
