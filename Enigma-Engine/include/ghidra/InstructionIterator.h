#pragma once

#include <ghidra/Instruction.h>

namespace ghidra {

class InstructionIterator {
public:
    virtual ~InstructionIterator() = default;

    virtual bool hasNext() = 0;
    virtual Instruction* next() = 0;
};

} // namespace ghidra
