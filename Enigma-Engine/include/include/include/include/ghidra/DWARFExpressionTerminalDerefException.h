#pragma once

#include "DWARFExpressionUnsupportedOpException.h"

namespace ghidra {

class Varnode;
class DWARFExpressionInstruction;

class DWARFExpressionTerminalDerefException : public DWARFExpressionUnsupportedOpException {
private:
    const Varnode* varnode;

public:
    DWARFExpressionTerminalDerefException(const DWARFExpressionInstruction* op, const Varnode* varnode)
        : DWARFExpressionUnsupportedOpException(op), varnode(varnode) {}

    const Varnode* getVarnode() const { return varnode; }
};

} // namespace ghidra
