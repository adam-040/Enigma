#pragma once

#include <ghidra/ScalarOperandAnalyzer.h>

namespace ghidra {

class ElfScalarOperandAnalyzer : public ScalarOperandAnalyzer {
public:
    ElfScalarOperandAnalyzer();
    virtual ~ElfScalarOperandAnalyzer() = default;

    virtual     bool canAnalyze(Program* program) const override;
    bool getDefaultEnablement(Program* program) const override;

protected:
    bool addReference(Program* program, Instruction* instr, int opIndex,
                      const AddressSpace* space, Scalar* scalar) override;
};

} // namespace ghidra
