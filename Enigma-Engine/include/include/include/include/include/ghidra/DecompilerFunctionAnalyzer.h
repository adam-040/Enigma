#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class DecompilerFunctionAnalyzer : public AbstractAnalyzer {
public:
    DecompilerFunctionAnalyzer();
    virtual ~DecompilerFunctionAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool getDefaultEnablement(Program* program) const override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    int clearLevelOption_ = 1;
    bool commitDataTypesOption_ = true;
    bool commitVoidReturnOption_ = false;
    int decompilerTimeoutSecondsOption_ = 60;
};

} // namespace ghidra
