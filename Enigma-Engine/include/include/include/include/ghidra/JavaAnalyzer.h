#pragma once

#include <ghidra/AbstractJavaAnalyzer.h>

namespace ghidra {

class JavaAnalyzer : public AbstractJavaAnalyzer {
public:
    JavaAnalyzer();
    ~JavaAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool analyze(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
