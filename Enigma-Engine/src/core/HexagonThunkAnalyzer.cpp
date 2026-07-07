#include <ghidra/HexagonThunkAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AutoNaming.h>
#include <ghidra/Msg.h>
#include <cstdint>

namespace ghidra {

HexagonThunkAnalyzer::HexagonThunkAnalyzer()
    : AbstractAnalyzer("Hexagon Thunks",
                       "Detects common Thunk pattern used within Hexagon code.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS);
    setDefaultEnablement(true);
}

bool HexagonThunkAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "Hexagon";
}

bool HexagonThunkAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool HexagonThunkAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Searching for Hexagon thunks...");

    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!listing || !funcMgr) return true;

    // Hexagon thunks are short jump trampolines.
    // Look for "jump #target" patterns at the end of small code sequences.
    auto instructions = listing->getInstructions(set);
    int thunksFound = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;
        if (!instr->getFlowType()->isJump()) continue;

        Address target;
        auto refs = program->getReferenceManager()->getReferencesFrom(instr->getAddress());
        for (auto* ref : refs) {
            if (ref->getReferenceType()->isJump()) {
                target = ref->getToAddress();
                break;
            }
        }
        if (!target.isValid()) continue;

        // Check if this looks like a thunk (short jump to another function)
        if (!funcMgr->getFunctionAt(instr->getMinAddress()) &&
            funcMgr->getFunctionAt(target)) {
            AddressSet body(instr->getMinAddress(), instr->getMinAddress());
            Function* thunk = funcMgr->createFunction(
                AutoNaming::nameVal("thunk", static_cast<uint64_t>(instr->getMinAddress().getOffset())),
                instr->getMinAddress(), body, SourceType::ANALYSIS);
            if (thunk) ++thunksFound;
        }
    }

    if (thunksFound > 0) {
        Msg::info(getName(), "Found " + std::to_string(thunksFound) + " Hexagon thunks.");
    }
    return true;
}

} // namespace ghidra
