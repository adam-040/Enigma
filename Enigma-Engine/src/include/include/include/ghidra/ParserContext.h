#pragma once

#include <ghidra/Address.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <vector>
#include <string>
#include <memory>

namespace ghidra {

class PcodeOp;
class Varnode;
class FlowType;

class ParserContext {
public:
    virtual ~ParserContext() = default;
    virtual Address getAddress() const = 0;
    virtual int getLength() const = 0;
    virtual std::vector<PcodeOp*> getPcodeOps() const = 0;
    virtual std::vector<Varnode*> getInputs() const = 0;
    virtual std::vector<Varnode*> getOutputs() const = 0;
    virtual FlowType* getFlowType() const = 0;
    virtual RegisterValue* getRegisterValue(Register* reg) const = 0;
    virtual void setRegisterValue(Register* reg, RegisterValue* value) = 0;
    virtual std::string getMnemonic() const = 0;
    virtual std::vector<std::string> getOpRepresentations() const = 0;
};

} // namespace ghidra
