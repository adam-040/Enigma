#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class FBPK_Analyzer : public AbstractAnalyzer {
public:
    FBPK_Analyzer();
    ~FBPK_Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
