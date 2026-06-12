#include <ghidra/Pic17c7xxAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/Register.h>
#include <ghidra/Scalar.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Language.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>

namespace ghidra {

Pic17c7xxAnalyzer::Pic17c7xxAnalyzer()
    : AbstractAnalyzer("PIC-17C7xx",
                       "Analyzes PIC-17C7xx instructions.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY.after().after().after());
    setDefaultEnablement(true);
}

bool Pic17c7xxAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "PIC-17";
}

bool Pic17c7xxAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Pic17c7xxAnalyzer::added(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Analyzing PIC-17C7xx instructions...");

    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!listing || !funcMgr) return true;

    // Scan for computed GOTO targets and create function entries
    auto instructions = listing->getInstructions(set);
    int created = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;
        if (!instr->getFlowType()->isJump()) continue;

        // Check for operand scalars that look like code addresses
        for (int i = 0; i < instr->getNumOperands(); ++i) {
            auto scalars = instr->getOperandScalars(i);
            for (auto* sc : scalars) {
                int64_t val = sc->getSignedValue();
                if (val < 0x100) continue;
                AddressSpace* space = const_cast<AddressSpace*>(
                    instr->getMinAddress().getAddressSpace());
                Address target(space, val);
                if (!program->getMemory()->getBlock(target)) continue;
                if (funcMgr->getFunctionAt(target) || funcMgr->getFunctionContaining(target)) continue;

                AddressSet body(target, target);
                funcMgr->createFunction("pic17_func_" + std::to_string(val),
                                        target, body, SourceType::ANALYSIS);
                ++created;
            }
        }
    }

    if (created > 0) {
        Msg::info(getName(), "Created " + std::to_string(created) + " function entries.");
    }
    return true;
}

} // namespace ghidra
