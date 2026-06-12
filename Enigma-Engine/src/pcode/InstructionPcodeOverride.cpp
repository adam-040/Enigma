#include <ghidra/InstructionPcodeOverride.h>
#include <ghidra/Program.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/PcodeInject.h>
#include <ghidra/Msg.h>

namespace ghidra {

InstructionPcodeOverride::InstructionPcodeOverride(Instruction* instr)
    : instr_(instr) {}

void InstructionPcodeOverride::initReferences() {
    if (refsInitialized_) return;
    refsInitialized_ = true;
    if (!instr_) return;

    for (Reference* ref : instr_->getReferencesFrom()) {
        if (!ref) continue;
        if (!ref->isPrimary() || !ref->getToAddress().isMemoryAddress()) {
            continue;
        }
        const RefType* type = ref->getReferenceType();
        if (!type) continue;
        if (type->isOverride()) {
            primaryOverridingReferences_.push_back(ref);
        } else if (type->isCall() && !primaryCallAddress_.isValid()) {
            primaryCallAddress_ = ref->getToAddress();
        }
    }
}

Address InstructionPcodeOverride::getInstructionStart() {
    return instr_ ? instr_->getAddress() : Address::NO_ADDRESS;
}

FlowOverride InstructionPcodeOverride::getFlowOverride() {
    return instr_ ? instr_->getFlowOverride() : FlowOverride::NONE;
}

Address InstructionPcodeOverride::getOverridingReference(const RefType* type) {
    if (!type || !type->isOverride()) {
        return Address::NO_ADDRESS;
    }
    initReferences();
    Address overrideAddress;
    bool hasOne = false;
    for (Reference* ref : primaryOverridingReferences_) {
        if (ref->getReferenceType() && *(ref->getReferenceType()) == *type) {
            if (!hasOne) {
                overrideAddress = ref->getToAddress();
                hasOne = true;
            } else {
                return Address::NO_ADDRESS; // Only allow one primary reference of each type
            }
        }
    }
    return overrideAddress;
}

Address InstructionPcodeOverride::getFallThroughOverride() {
    if (!instr_) return Address::NO_ADDRESS;
    Address defaultFallAddr = instr_->getDefaultFallThrough();
    Address fallAddr = instr_->getFallThrough();
    if (fallAddr.isValid() && (instr_->isLengthOverridden() || !(fallAddr == defaultFallAddr))) {
        return fallAddr;
    }
    return Address::NO_ADDRESS;
}

bool InstructionPcodeOverride::hasCallFixup(const Address& callDestAddr) {
    if (!instr_) return false;
    Program* program = instr_->getProgram();
    if (!program) return false;
    Function* func = program->getFunctionManager()->getFunctionAt(callDestAddr);
    if (!func) return false;
    return !func->getCallFixup().empty();
}

PcodeInject* InstructionPcodeOverride::getCallFixup(const Address& callDestAddr) {
    if (!instr_) return nullptr;
    Program* program = instr_->getProgram();
    if (!program) return nullptr;
    Function* func = program->getFunctionManager()->getFunctionAt(callDestAddr);
    if (!func) return nullptr;
    const std::string& fixupName = func->getCallFixup();
    if (fixupName.empty()) return nullptr;
    CompilerSpec* compSpec = program->getCompilerSpec();
    if (!compSpec) return nullptr;
    PcodeInjectLibrary* injectLib = compSpec->getPcodeInjectLibrary();
    if (!injectLib) return nullptr;
    PcodeInject* fixup = injectLib->getInject(fixupName);
    if (!fixup) {
        Msg::warn("InstructionPcodeOverride", "Undefined call-fixup: " + fixupName);
    }
    return fixup;
}

bool InstructionPcodeOverride::hasPotentialOverride() {
    initReferences();
    return !primaryOverridingReferences_.empty();
}

Address InstructionPcodeOverride::getPrimaryCallReference() {
    initReferences();
    return primaryCallAddress_;
}

} // namespace ghidra
