#pragma once

#include <ghidra/StackFrame.h>
#include <map>
#include <memory>

namespace ghidra {

class Function;
class VariableImpl;

class StackFrameImpl : public StackFrame {
public:
    explicit StackFrameImpl(Function* function);

    Function* getFunction() const override { return function_; }
    int getFrameSize() const override { return frameSize_; }
    int getLocalSize() const override { return localSize_; }
    int getParameterSize() const override { return parameterSize_; }
    int getParameterOffset() const override { return parameterOffset_; }
    bool isParameterOffset(int offset) const override;

    void setLocalSize(int size) override { localSize_ = size; }
    void setReturnAddressOffset(int offset) override { returnAddrOffset_ = offset; }
    int getReturnAddressOffset() const override { return returnAddrOffset_; }

    Variable* getVariableContaining(int offset) override;
    Variable* createVariable(const std::string& name, int offset,
                              DataType* dataType, SourceType source) override;
    void clearVariable(int offset) override;

    std::vector<Variable*> getStackVariables() override;
    std::vector<Variable*> getParameters() override;
    std::vector<Variable*> getLocals() override;

    bool growsNegative() const override { return true; }

    void setPurgeSize(int size) override { purgeSize_ = size; }
    int getPurgeSize() const override { return purgeSize_; }

    void setFrameSize(int size) { frameSize_ = size; }
    void setParameterSize(int size) { parameterSize_ = size; }
    void setParameterOffset(int offset) { parameterOffset_ = offset; }

private:
    Function* function_ = nullptr;
    int frameSize_ = 0;
    int localSize_ = 0;
    int parameterSize_ = 0;
    int parameterOffset_ = 0;
    int returnAddrOffset_ = 0;
    int purgeSize_ = 0;
    std::map<int, std::unique_ptr<VariableImpl>> variables_;
};

} // namespace ghidra
