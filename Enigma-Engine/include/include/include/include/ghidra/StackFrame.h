#pragma once

#include <ghidra/Function.h>
#include <ghidra/Variable.h>
#include <ghidra/DataType.h>
#include <ghidra/SourceType.h>
#include <vector>

namespace ghidra {

class StackFrame {
public:
    static constexpr int GROWS_NEGATIVE = -1;
    static constexpr int GROWS_POSITIVE = 1;
    static constexpr int UNKNOWN_PARAM_OFFSET = 128 * 1024;

    virtual ~StackFrame() = default;

    virtual Function* getFunction() const = 0;
    virtual int getFrameSize() const = 0;
    virtual int getLocalSize() const = 0;
    virtual int getParameterSize() const = 0;
    virtual int getParameterOffset() const = 0;
    virtual bool isParameterOffset(int offset) const = 0;

    virtual void setLocalSize(int size) = 0;
    virtual void setReturnAddressOffset(int offset) = 0;
    virtual int getReturnAddressOffset() const = 0;

    virtual Variable* getVariableContaining(int offset) = 0;
    virtual Variable* createVariable(const std::string& name, int offset,
                                      DataType* dataType, SourceType source) = 0;
    virtual void clearVariable(int offset) = 0;

    virtual std::vector<Variable*> getStackVariables() = 0;
    virtual std::vector<Variable*> getParameters() = 0;
    virtual std::vector<Variable*> getLocals() = 0;

    virtual bool growsNegative() const = 0;

    virtual void setPurgeSize(int size) = 0;
    virtual int getPurgeSize() const = 0;
};

} // namespace ghidra
