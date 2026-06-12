#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class ToyAnalyzer : public ConstantPropagationAnalyzer {
public:
    ToyAnalyzer();
    ~ToyAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

protected:
    static constexpr const char* PROCESSOR_NAME = "Toy";
};

} // namespace ghidra
