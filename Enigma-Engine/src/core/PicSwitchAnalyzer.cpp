#include <ghidra/PicSwitchAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/AddressSet.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Msg.h>
#include <cstdint>
#include <vector>

namespace ghidra {

PicSwitchAnalyzer::PicSwitchAnalyzer()
    : AbstractAnalyzer("PIC Switch Tables",
                       "Analyzes PIC Switch instructions.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY.after().after().after().after());
    setDefaultEnablement(true);
}

bool PicSwitchAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    std::string name = program->getLanguage()->getProcessor().getName();
    return name == "PIC-12" || name == "PIC-16" || name == "PIC-17" || name == "PIC-18";
}

bool PicSwitchAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool PicSwitchAnalyzer::added(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Analyzing PIC switch tables...");

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!memory || !listing || !symTable) return true;

    // Scan for indirect jump instructions and try to recover switch tables
    auto instructions = listing->getInstructions(set);
    int tablesFound = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;
        if (!instr->getFlowType()->isJump() || !instr->getFlowType()->isComputed()) continue;

        // Read bytes after the instruction as potential table data
        Address scanAddr;
        try {
            scanAddr = instr->getMinAddress().add(instr->getLength());
        } catch (...) { continue; }

        int entrySize = 2; // PIC typically uses 2-byte entries
        int maxEntries = 128;
        int entriesFound = 0;

        for (int i = 0; i < maxEntries; ++i) {
            Address entryAddr;
            try { entryAddr = scanAddr.add(i * entrySize); } catch (...) { break; }
            if (listing->getInstructionContaining(entryAddr)) break;

            uint8_t bytes[2] = {};
            MemoryBlock* blk = memory->getBlock(entryAddr);
            if (!blk || blk->getBytes(entryAddr, bytes, 2) != 2) break;

            uint16_t targetVal = static_cast<uint16_t>(bytes[0]) |
                                 (static_cast<uint16_t>(bytes[1]) << 8);
            if (targetVal < 0x100) break; // Not a valid PIC code address

            Address targetAddr(scanAddr.getAddressSpace(), static_cast<int64_t>(targetVal));
            if (!memory->getBlock(targetAddr)) break;

            symTable->createLabel(targetAddr, "pic_switch_" + std::to_string(i),
                                  SourceType::ANALYSIS);
            ++entriesFound;
        }

        if (entriesFound > 0) {
            program->getBookmarkManager()->setBookmark(
                instr->getMinAddress(), "ANALYSIS",
                "PIC switch table: " + std::to_string(entriesFound) + " cases");
            ++tablesFound;
        }
    }

    if (tablesFound > 0) {
        Msg::info(getName(), "Found " + std::to_string(tablesFound) + " switch tables.");
    }
    return true;
}

} // namespace ghidra
