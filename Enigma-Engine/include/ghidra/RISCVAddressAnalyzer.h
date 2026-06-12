#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class RISCVAddressAnalyzer : public ConstantPropagationAnalyzer {
public:
    RISCVAddressAnalyzer();
    ~RISCVAddressAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

private:
    void checkForGlobalGP(Program* program);

    static constexpr const char* GLOBAL_POINTER_SYMBOL = "__global_pointer$";
    static constexpr const char* PROCESSOR_NAME = "RISCV";
    static constexpr const char* REGISTER_GP = "gp";

    Register* gp_ = nullptr;
    Address gpAssumptionValue_;
};

} // namespace ghidra
