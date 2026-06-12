#pragma once

#include <ghidra/Address.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/Register.h>

namespace ghidra {

class DefaultProgramContext {
public:
    virtual ~DefaultProgramContext() = default;
    virtual void setDefaultValue(RegisterValue* registerValue, const Address& start, const Address& end) = 0;
    virtual RegisterValue* getDefaultValue(Register* reg, const Address& address) = 0;
};

} // namespace ghidra
