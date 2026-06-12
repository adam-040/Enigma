#pragma once

#include <ghidra/MemBuffer.h>
#include <ghidra/ProcessorContext.h>
#include <vector>
#include <string>

namespace ghidra {

class ParserContext;
class FlowType;
class RegisterValue;
class VariableOffset;
class Scalar;
class PcodeOp;

class InstructionPrototype {
public:
    static constexpr int INVALID_DEPTH_CHANGE = 1 << 24;

    virtual ~InstructionPrototype() = default;
    virtual ParserContext* getParserContext(MemBuffer* buf, ProcessorContext* processorContext) = 0;
    virtual int getInstructionLength() const = 0;
    virtual int getDelaySlotDepth() const = 0;
    virtual FlowType* getFlowType() = 0;
    virtual std::vector<RegisterValue*> getContextChanges() = 0;
    virtual std::vector<VariableOffset*> getFlows() = 0;
    virtual std::vector<Scalar*> getScalars() = 0;
    virtual std::vector<PcodeOp*> getPcodeOps() = 0;
    virtual bool isEquivalent(const InstructionPrototype* other) const = 0;
};

} // namespace ghidra
