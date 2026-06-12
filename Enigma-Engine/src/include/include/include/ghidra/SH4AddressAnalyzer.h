#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class VarnodeContext;

class SH4AddressAnalyzer : public ConstantPropagationAnalyzer {
public:
    SH4AddressAnalyzer();
    ~SH4AddressAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

public:
    bool checkComputedRelativeBranch(Program* program, TaskMonitor* monitor,
                                      Instruction* instr, const Address& address,
                                      const RefType* refType, int pcodeop);
    void propagateR12ToCall(Program* program, VarnodeContext* context, const Address& address);

    static constexpr const char* PROCESSOR_NAME = "SuperH4";
    static constexpr const char* OPT_PROPAGATE_R12 = "Propagate constant R12";

    bool propagateR12_ = true;
    Register* r12_ = nullptr;
};

} // namespace ghidra
