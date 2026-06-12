#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class DexMarkupSwitchTableAnalyzer : public AbstractAnalyzer {
public:
    DexMarkupSwitchTableAnalyzer();
    ~DexMarkupSwitchTableAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
