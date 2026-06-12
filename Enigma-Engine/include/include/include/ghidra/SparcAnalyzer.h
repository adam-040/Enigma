#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class SparcAnalyzer : public ConstantPropagationAnalyzer {
public:
    SparcAnalyzer();
    ~SparcAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

protected:
    static constexpr const char* PROCESSOR_NAME = "Sparc";
    static constexpr const char* O7_CALLRETURN_NAME = "Call/Return o7 check";

    bool o7CallReturnAnalysis_ = true;
};

} // namespace ghidra
