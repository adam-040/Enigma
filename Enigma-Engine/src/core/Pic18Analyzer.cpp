#include <ghidra/Pic18Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/Register.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Language.h>
#include <ghidra/AddressSet.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>

namespace ghidra {

Pic18Analyzer::Pic18Analyzer()
    : AbstractAnalyzer("PIC-18",
                       "Analyzes PIC-18 instructions.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY.after().after().after());
    setDefaultEnablement(true);
}

bool Pic18Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "PIC-18";
}

bool Pic18Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Pic18Analyzer::added(Program* program, const AddressSetView& set,
                           TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Analyzing PIC-18 instructions...");

    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!listing || !funcMgr || !refMgr) return true;

    // PIC-18 uses CALL and GOTO instructions with 16-bit addresses.
    // Find call targets and create functions.
    auto instructions = listing->getInstructions(set);
    int created = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;
        if (!instr->getFlowType()->isCall()) continue;

        auto refs = refMgr->getReferencesFrom(instr->getAddress());
        for (auto* ref : refs) {
            if (monitor->isCancelled()) break;
            if (!ref->getReferenceType()->isCall()) continue;
            Address toAddr = ref->getToAddress();
            if (!toAddr.isValid()) continue;
            if (funcMgr->getFunctionAt(toAddr) || funcMgr->getFunctionContaining(toAddr)) continue;

            AddressSet body(toAddr, toAddr);
            funcMgr->createFunction("pic18_func_" + std::to_string(toAddr.getOffset()),
                                    toAddr, body, SourceType::ANALYSIS);
            ++created;
        }
    }

    if (created > 0) {
        Msg::info(getName(), "Created " + std::to_string(created) + " function entries.");
    }
    return true;
}

} // namespace ghidra
