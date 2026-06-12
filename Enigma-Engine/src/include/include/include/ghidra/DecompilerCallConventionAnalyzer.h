#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class DecompilerCallConventionAnalyzer : public AbstractAnalyzer {
public:
    DecompilerCallConventionAnalyzer();
    ~DecompilerCallConventionAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
