#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class LoongsonAnalyzer : public ConstantPropagationAnalyzer {
public:
    LoongsonAnalyzer();
    ~LoongsonAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

private:
    static constexpr const char* PROCESSOR_NAME = "Loongarch";
    Register* linkRegister_ = nullptr;
};

} // namespace ghidra
