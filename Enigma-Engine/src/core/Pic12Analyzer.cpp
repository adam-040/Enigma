#include <ghidra/Pic12Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/Register.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Language.h>
#include <ghidra/LanguageID.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/Msg.h>
#include <cstdint>

namespace ghidra {

Pic12Analyzer::Pic12Analyzer()
    : AbstractAnalyzer("PIC-12C5xx or PIC-16C5x",
                       "Analyzes PIC 12-bit instructions (PIC-12C5xx or PIC-16C5x).",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY.after().after().after());
    setDefaultEnablement(true);
}

bool Pic12Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    LanguageID lid = program->getLanguage()->getLanguageID();
    return lid == LanguageID("PIC-12:LE:16:PIC-12C5xx") ||
           lid == LanguageID("PIC-16:LE:16:PIC-16C5x");
}

bool Pic12Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Pic12Analyzer::added(Program* program, const AddressSetView& set,
                           TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Analyzing PIC-12 instructions...");

    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!listing || !funcMgr) return true;

    // Mark computed jump targets that go to undefined code
    auto instructions = listing->getInstructions(set);
    int marked = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;
        if (!instr->getFlowType()->isJump() || !instr->getFlowType()->isComputed()) continue;

        auto refs = program->getReferenceManager()->getReferencesFrom(instr->getAddress());
        for (auto* ref : refs) {
            if (monitor->isCancelled()) break;
            Address toAddr = ref->getToAddress();
            if (!toAddr.isValid()) continue;
            if (funcMgr->getFunctionAt(toAddr) || funcMgr->getFunctionContaining(toAddr)) continue;

            AddressSet body(toAddr, toAddr);
            funcMgr->createFunction("pic12_func_" + std::to_string(toAddr.getOffset()),
                                    toAddr, body, SourceType::ANALYSIS);
            ++marked;
        }
    }

    if (marked > 0) {
        Msg::info(getName(), "Created " + std::to_string(marked) + " function entries.");
    }
    return true;
}

} // namespace ghidra
