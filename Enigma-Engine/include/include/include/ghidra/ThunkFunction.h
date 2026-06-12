#pragma once

#include <ghidra/Function.h>
#include <ghidra/Address.h>

namespace ghidra {

class ThunkFunction : public Function {
public:
    ~ThunkFunction() override = default;

    virtual void setDestinationFunction(Function* function) = 0;
    virtual Address getDestinationFunctionEntryPoint() = 0;
};

} // namespace ghidra
