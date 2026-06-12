#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class Pic18Analyzer : public AbstractAnalyzer {
public:
    Pic18Analyzer();
    ~Pic18Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
