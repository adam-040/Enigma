#include <ghidra/PefDebugAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>
#include <vector>

namespace ghidra {

namespace {

// Scan for PEF loader strings which indicate debug symbols
static void findPefDebugSymbols(Program* program, TaskMonitor* monitor, int& found) {
    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    if (!memory || !symTable) return;

    for (auto* block : memory->getBlocks()) {
        if (monitor->isCancelled()) break;
        std::string name = block->getName();
        if (name.find("PEF") == std::string::npos &&
            name.find("pef") == std::string::npos &&
            name.find("LOAD") == std::string::npos) continue;

        Address start = block->getStart();
        Address end = block->getEnd();
        int64_t size = end.getOffset() - start.getOffset() + 1;
        if (size > 256 * 1024) size = 256 * 1024;

        std::vector<uint8_t> buf(static_cast<size_t>(size));
        int read = block->getBytes(start, buf.data(), static_cast<int>(size));
        if (read <= 0) continue;

        // Scan for printable strings that look like symbol names
        std::string current;
        for (int64_t i = 0; i < static_cast<int64_t>(size) && !monitor->isCancelled(); ++i) {
            char c = static_cast<char>(buf[static_cast<size_t>(i)]);
            if (std::isprint(static_cast<unsigned char>(c)) && c != ' ') {
                current += c;
            } else {
                if (current.size() >= 4 && current.size() <= 256 &&
                    current.find('.') != std::string::npos) {
                    Address symAddr(start.getAddressSpace(), start.getOffset() + i -
                                     static_cast<int64_t>(current.size()));
                    if (!symTable->getPrimarySymbol(symAddr) &&
                        program->getListing()->isUndefined(symAddr)) {
                        symTable->createLabel(symAddr, "pef_" + current,
                                              SourceType::ANALYSIS);
                        ++found;
                    }
                }
                current.clear();
            }
        }
    }
}

} // anonymous namespace

PefDebugAnalyzer::PefDebugAnalyzer()
    : AbstractAnalyzer("PEF Debug Symbols",
                       "Extracts debug symbols from PEF (Mac OS Classic) binaries.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool PefDebugAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Mac OS preferred executable format (PEF)";
}

bool PefDebugAnalyzer::added(Program* program, const AddressSetView& set,
                              TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Extracting PEF debug symbols...");

    int found = 0;
    findPefDebugSymbols(program, monitor, found);

    if (found > 0) {
        Msg::info(getName(), "Extracted " + std::to_string(found) +
                  " PEF debug symbols.");
    }
    return true;
}

} // namespace ghidra
