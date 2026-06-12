#include <ghidra/RISCVAddressAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/Register.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

RISCVAddressAnalyzer::RISCVAddressAnalyzer()
    : ConstantPropagationAnalyzer(PROCESSOR_NAME) {
}

bool RISCVAddressAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getProcessor().getName() != PROCESSOR_NAME) return false;
    RISCVAddressAnalyzer* self = const_cast<RISCVAddressAnalyzer*>(this);
    self->gp_ = program->getRegister(REGISTER_GP);
    return gp_ != nullptr;
}

void RISCVAddressAnalyzer::checkForGlobalGP(Program* program) {
    auto symbols = program->getSymbolTable()->getLabelOrFunctionSymbols(
        GLOBAL_POINTER_SYMBOL, program->getGlobalNamespace());
    if (!symbols.empty()) {
        gpAssumptionValue_ = symbols[0]->getAddress();
    }
}

bool RISCVAddressAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    gpAssumptionValue_ = Address();
    checkForGlobalGP(program);
    return ConstantPropagationAnalyzer::added(program, set, monitor, log);
}

AddressSet RISCVAddressAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                                 const AddressSetView* flowSet,
                                                 SymbolicPropogator* symEval,
                                                 TaskMonitor* monitor) {
    Function* func = program->getFunctionManager()->getFunctionContaining(flowStart);

    if (func && gp_ && gpAssumptionValue_.isValid()) {
        ProgramContext* progCtx = program->getProgramContext();
        RegisterValue* gpVal = progCtx->getRegisterValue(gp_, flowStart);
        if (!gpVal) {
            int size = gp_->getBitLength() / 8;
            if (size <= 0) size = 4;
            gpVal = new RegisterValue(gp_, static_cast<uint64_t>(gpAssumptionValue_.getOffset()), size);
            progCtx->setRegisterValue(gpVal, func->getEntryPoint(), func->getEntryPoint());
        }
    }

    ConstantPropagationContextEvaluator eval(monitor, trustWriteMemOption);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
}

} // namespace ghidra
