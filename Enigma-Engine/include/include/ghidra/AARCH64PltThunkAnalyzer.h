#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class AARCH64PltThunkAnalyzer : public AbstractAnalyzer {
public:
    AARCH64PltThunkAnalyzer();
    ~AARCH64PltThunkAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
