#pragma once

#include <ghidra/FunctionAnalyzer.h>

namespace ghidra {

class CreateThunkAnalyzer : public FunctionAnalyzer {
public:
    CreateThunkAnalyzer();
    ~CreateThunkAnalyzer() override = default;

    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;
};

} // namespace ghidra
