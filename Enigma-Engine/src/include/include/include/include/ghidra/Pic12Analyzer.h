#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class Pic12Analyzer : public AbstractAnalyzer {
public:
    Pic12Analyzer();
    ~Pic12Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
