#pragma once
#include <ghidra/Variable.h>

namespace ghidra {

class LocalVariable : virtual public Variable {
public:
    virtual ~LocalVariable() = default;
    virtual bool setFirstUseOffset(int firstUseOffset) = 0;
};

} // namespace ghidra
