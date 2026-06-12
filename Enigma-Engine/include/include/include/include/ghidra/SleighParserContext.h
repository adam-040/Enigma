#pragma once

#include <ghidra/ParserContext.h>
#include <ghidra/SleighInstructionPrototype.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/AddressSpace.h>

namespace ghidra {

class SleighParserContext : public ParserContext {
public:
    SleighParserContext(MemBuffer* memBuf, SleighInstructionPrototype* prototype)
        : memBuffer_(memBuf), prototype_(prototype) {
        if (memBuf) {
            addr_ = memBuf->getAddress();
        }
    }

    ~SleighParserContext() override = default;

    Address getAddress() const override { return addr_; }
    int getLength() const override { return prototype_ ? prototype_->getInstructionLength() : 0; }
    
    std::vector<PcodeOp*> getPcodeOps() const override {
        return prototype_ ? prototype_->getPcodeOps() : std::vector<PcodeOp*>();
    }
    
    std::vector<Varnode*> getInputs() const override { return {}; }
    std::vector<Varnode*> getOutputs() const override { return {}; }
    
    FlowType* getFlowType() const override {
        return prototype_ ? prototype_->getFlowType() : nullptr;
    }
    
    RegisterValue* getRegisterValue(Register* reg) const override { return nullptr; }
    void setRegisterValue(Register* reg, RegisterValue* value) override {}
    
    std::string getMnemonic() const override { return ""; }
    std::vector<std::string> getOpRepresentations() const override { return {}; }

    // Sleigh specific methods
    SleighInstructionPrototype* getPrototype() const { return prototype_; }
    MemBuffer* getMemBuffer() const { return memBuffer_; }

private:
    MemBuffer* memBuffer_ = nullptr;
    SleighInstructionPrototype* prototype_ = nullptr;
    Address addr_;
};

} // namespace ghidra
