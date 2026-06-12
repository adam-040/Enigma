#pragma once

#include "DWARFExpressionException.h"
#include <string>

namespace ghidra {

class DWARFExpressionInstruction;

class DWARFExpressionUnsupportedOpException : public DWARFExpressionException {
private:
    const DWARFExpressionInstruction* instr;

public:
    explicit DWARFExpressionUnsupportedOpException(const DWARFExpressionInstruction* instr)
        : DWARFExpressionException("Unsupported instruction"), instr(instr) {}

    const DWARFExpressionInstruction* getInstruction() const { return instr; }
};

} // namespace ghidra
