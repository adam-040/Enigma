#include <ghidra/NDS32Analyzer.h>
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

NDS32Analyzer::NDS32Analyzer()
    : ConstantPropagationAnalyzer(PROCESSOR_NAME) {
}

bool NDS32Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getProcessor().getName() != PROCESSOR_NAME) return false;
    NDS32Analyzer* self = const_cast<NDS32Analyzer*>(this);
    self->gp_ = program->getRegister("gp");
    return gp_ != nullptr;
}

void NDS32Analyzer::registerOptions(Options& options, Program* program) {
    ConstantPropagationAnalyzer::registerOptions(options, program);
    options.registerBool("Recover global GP register writes",
                         recoverGp_,
                         "Reads the global GP value from the symbol _SDA_BASE_");
}

void NDS32Analyzer::optionsChanged(Options& options, Program* program) {
    ConstantPropagationAnalyzer::optionsChanged(options, program);
    recoverGp_ = options.getBool("Recover global GP register writes");
}

void NDS32Analyzer::checkForGlobalGP(Program* program) {
    if (!recoverGp_) return;
    auto symbols = program->getSymbolTable()->getLabelOrFunctionSymbols(
        GP_SYMBOL, program->getGlobalNamespace());
    if (!symbols.empty()) {
        gpAssumptionValue_ = symbols[0]->getAddress();
    }
}

bool NDS32Analyzer::added(Program* program, const AddressSetView& set,
                           TaskMonitor* monitor, MessageLog& log) {
    gpAssumptionValue_ = Address();
    checkForGlobalGP(program);
    return ConstantPropagationAnalyzer::added(program, set, monitor, log);
}

AddressSet NDS32Analyzer::flowConstants(Program* program, const Address& flowStart,
                                         const AddressSetView* flowSet,
                                         SymbolicPropogator* symEval,
                                         TaskMonitor* monitor) {
    Function* func = program->getFunctionManager()->getFunctionContaining(flowStart);
    AddressSet coveredSet;

    Address currentGP = gpAssumptionValue_;
    if (func && currentGP.isValid()) {
        Address startAddr = func->getEntryPoint();
        ProgramContext* progCtx = program->getProgramContext();
        RegisterValue* gpVal = progCtx->getRegisterValue(gp_, startAddr);
        if (!gpVal) {
            int size = gp_->getBitLength() / 8;
            if (size <= 0) size = 4;
            gpVal = new RegisterValue(gp_, static_cast<uint64_t>(currentGP.getOffset()), size);
            progCtx->setRegisterValue(gpVal, startAddr, startAddr);
        }
    }

    ConstantPropagationContextEvaluator eval(monitor, trustWriteMemOption);
    eval.setTrustWritableMemory(trustWriteMemOption)
        ->setMinSpeculativeOffset(minSpeculativeRefAddress)
        ->setMaxSpeculativeOffset(maxSpeculativeRefAddress)
        ->setMinStoreLoadOffset(minStoreLoadRefAddress)
        ->setCreateComplexDataFromPointers(createComplexDataFromPointers);

    AddressSet resultSet = symEval->flowConstants(flowStart, nullptr, &eval, true, monitor);
    resultSet.add(coveredSet);
    return resultSet;
}

} // namespace ghidra
