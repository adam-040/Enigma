#pragma once

#include <ghidra/CodeUnit.h>

namespace ghidra {

class CodeUnitIterator {
public:
    virtual ~CodeUnitIterator() = default;

    virtual bool hasNext() = 0;
    virtual CodeUnit* next() = 0;
};

class EmptyCodeUnitIterator : public CodeUnitIterator {
public:
    bool hasNext() override { return false; }
    CodeUnit* next() override { return nullptr; }
    static EmptyCodeUnitIterator& instance() {
        static EmptyCodeUnitIterator inst;
        return inst;
    }
};

} // namespace ghidra
