#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class NDS32Analyzer : public ConstantPropagationAnalyzer {
public:
    NDS32Analyzer();
    ~NDS32Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    void checkForGlobalGP(Program* program);

    static constexpr const char* PROCESSOR_NAME = "NDS32";
    static constexpr const char* GP_SYMBOL = "_SDA_BASE_";

    bool recoverGp_ = true;
    Address gpAssumptionValue_;
    Register* gp_ = nullptr;
};

} // namespace ghidra
