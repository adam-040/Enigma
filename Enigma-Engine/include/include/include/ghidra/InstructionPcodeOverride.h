#pragma once

#include <ghidra/PcodeOverride.h>
#include <ghidra/Instruction.h>
#include <ghidra/Reference.h>
#include <vector>

namespace ghidra {

/**
 * InstructionPcodeOverride caches overriding references from a listing Instruction
 * to be consumed during disassembly or decompilation.
 * Matches ghidra.program.model.listing.InstructionPcodeOverride
 */
class InstructionPcodeOverride : public PcodeOverride {
private:
    Instruction* instr_ = nullptr;
    bool callOverrideApplied_ = false;
    bool jumpOverrideApplied_ = false;
    bool callOtherCallOverrideApplied_ = false;
    bool callOtherJumpOverrideApplied_ = false;
    Address primaryCallAddress_;
    std::vector<Reference*> primaryOverridingReferences_;
    bool refsInitialized_ = false;

    void initReferences();

public:
    InstructionPcodeOverride(Instruction* instr);
    virtual ~InstructionPcodeOverride() = default;

    Address getInstructionStart() override;
    FlowOverride getFlowOverride() override;
    Address getOverridingReference(const RefType* type) override;
    Address getFallThroughOverride() override;
    bool hasCallFixup(const Address& callDestAddr) override;
    PcodeInject* getCallFixup(const Address& callDestAddr) override;

    void setCallOverrideRefApplied() override { callOverrideApplied_ = true; }
    bool isCallOverrideRefApplied() override { return callOverrideApplied_; }

    void setJumpOverrideRefApplied() override { jumpOverrideApplied_ = true; }
    bool isJumpOverrideRefApplied() override { return jumpOverrideApplied_; }

    void setCallOtherCallOverrideRefApplied() override { callOtherCallOverrideApplied_ = true; }
    bool isCallOtherCallOverrideRefApplied() override { return callOtherCallOverrideApplied_; }

    void setCallOtherJumpOverrideRefApplied() override { callOtherJumpOverrideApplied_ = true; }
    bool isCallOtherJumpOverrideApplied() override { return callOtherJumpOverrideApplied_; }

    bool hasPotentialOverride() override;
    Address getPrimaryCallReference() override;
};

} // namespace ghidra
