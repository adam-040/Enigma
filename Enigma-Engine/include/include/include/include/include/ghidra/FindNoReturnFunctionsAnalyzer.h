#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class FindNoReturnFunctionsAnalyzer : public AbstractAnalyzer {
public:
    FindNoReturnFunctionsAnalyzer();
    ~FindNoReturnFunctionsAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    void setFunctionNonReturning(Program* program, const Address& entry, MessageLog& log);
    void setNoFallThru(Program* program, const Address& entry);
    void fixCallingFunctionBody(Program* program, const Address& entry);

    int evidenceThresholdFunctions_ = 3;
    bool repairDamageEnabled_ = true;
    bool createBookmarksEnabled_ = true;
};

} // namespace ghidra
