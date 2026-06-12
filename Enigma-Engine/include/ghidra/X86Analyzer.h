#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

class X86Analyzer : public ConstantPropagationAnalyzer {
public:
    X86Analyzer();
    ~X86Analyzer() override = default;
    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;
};

} // namespace ghidra
