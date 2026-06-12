#pragma once

#include "DWARFExpressionException.h"
#include <string>

namespace ghidra {

class Varnode;

class DWARFExpressionValueException : public DWARFExpressionException {
private:
    const Varnode* vn;

public:
    explicit DWARFExpressionValueException(const Varnode* vn)
        : DWARFExpressionException("Unable to access value"), vn(vn) {}

    const Varnode* getVarnode() const { return vn; }
};

} // namespace ghidra
