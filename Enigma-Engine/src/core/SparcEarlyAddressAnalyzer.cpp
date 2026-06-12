#include <ghidra/SparcEarlyAddressAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Language.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Varnode.h>
#include <ghidra/AddressSet.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/Register.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

SparcEarlyAddressAnalyzer::SparcEarlyAddressAnalyzer()
    : SparcAnalyzer() {
    setPriority(AnalysisPriority::DISASSEMBLY);
}

bool SparcEarlyAddressAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    if (!o7CallReturnAnalysis_) {
        return true;
    }

    AddressSet unanalyzedSet(set);
    Register* linkReg = program->getLanguage()->getRegister("o7");
    if (!linkReg) return true;

    auto instructions = program->getListing()->getInstructions(unanalyzedSet);
    for (Instruction* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;

        if (!instr->getFlowType() || !instr->getFlowType()->isCall()) continue;
        if (instr->getFallThrough() == Address::NO_ADDRESS) continue;

        const auto& pcode = instr->getPcode();
        for (PcodeOp* pcodeOp : pcode) {
            Varnode* output = pcodeOp->getOutput();
            if (!output || output->getAddress() != linkReg->getAddress()) continue;
            if (pcodeOp->getNumInputs() < 1) continue;
            Varnode* input = pcodeOp->getInput(0);
            if (input->isConstant()) continue;

            instr->setFlowOverride(FlowOverride::CALL_RETURN);
            break;
        }
    }

    return true;
}

} // namespace ghidra
