#pragma once

#include <ghidra/InstructionPrototype.h>
#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <vector>
#include <string>

namespace ghidra {

class SleighLanguage;
class ConstructState;
class RegisterValue;
class VariableOffset;
class Scalar;
class PcodeOp;
class FlowRecord {
public:
    ConstructState* addressNode = nullptr;
    int flowFlags = 0;
};

class FlowSummary {
public:
    int delay = 0;
    bool hasCrossBuilds = false;
    bool hasNext2 = false;
    std::vector<FlowRecord> flowState;
};

class SleighInstructionPrototype : public InstructionPrototype {
public:
    static constexpr int RETURN = 0x01;
    static constexpr int CALL_INDIRECT = 0x02;
    static constexpr int BRANCH_INDIRECT = 0x04;
    static constexpr int CALL = 0x08;
    static constexpr int JUMPOUT = 0x10;
    static constexpr int NO_FALLTHRU = 0x20;
    static constexpr int BRANCH_TO_END = 0x40;
    static constexpr int CROSSBUILD = 0x80;
    static constexpr int LABEL = 0x100;

    SleighInstructionPrototype() = default;
    SleighInstructionPrototype(SleighLanguage* lang) : language_(lang) {}

    ParserContext* getParserContext(MemBuffer* buf, ProcessorContext* processorContext) override { return nullptr; }
    int getInstructionLength() const override { return length_; }
    int getDelaySlotDepth() const override { return delaySlotDepth_; }
    FlowType* getFlowType() override { return flowType_; }
    std::vector<RegisterValue*> getContextChanges() override { return contextChanges_; }
    std::vector<VariableOffset*> getFlows() override { return flows_; }
    std::vector<Scalar*> getScalars() override { return scalars_; }
    std::vector<PcodeOp*> getPcodeOps() override { return pcodeOps_; }
    bool isEquivalent(const InstructionPrototype* other) const override { return false; }

    FlowSummary getFlowSummary() const { return flowSummary_; }
    int getFlowFlags() const { return flowFlags_; }
    bool isInDelaySlot() const { return inDelaySlot_; }
    void setInDelaySlot(bool v) { inDelaySlot_ = v; }
    void setFlowFlags(int flags) { flowFlags_ = flags; }
    void setLength(int len) { length_ = len; }
    void setDelaySlotDepth(int d) { delaySlotDepth_ = d; }

private:
    SleighLanguage* language_ = nullptr;
    int length_ = 0;
    int delaySlotDepth_ = 0;
    int flowFlags_ = 0;
    bool inDelaySlot_ = false;
    FlowType* flowType_ = nullptr;
    FlowSummary flowSummary_;
    std::vector<RegisterValue*> contextChanges_;
    std::vector<VariableOffset*> flows_;
    std::vector<Scalar*> scalars_;
    std::vector<PcodeOp*> pcodeOps_;
};

} // namespace ghidra
