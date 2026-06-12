#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class PicSwitchAnalyzer : public AbstractAnalyzer {
public:
    PicSwitchAnalyzer();
    ~PicSwitchAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
