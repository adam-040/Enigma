#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class StackVariableAnalyzer : public AbstractAnalyzer {
public:
    StackVariableAnalyzer();
    ~StackVariableAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    bool doCreateLocalStackVars_ = true;
    bool doCreateStackParams_ = false;
};

} // namespace ghidra
