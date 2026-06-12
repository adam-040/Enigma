#pragma once

#include <ghidra/AbstractJavaAnalyzer.h>

namespace ghidra {

class JvmSwitchAnalyzer : public AbstractJavaAnalyzer {
public:
    JvmSwitchAnalyzer();
    ~JvmSwitchAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool analyze(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
