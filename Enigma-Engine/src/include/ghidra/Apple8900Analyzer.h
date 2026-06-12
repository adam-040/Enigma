#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class Apple8900Analyzer : public AbstractAnalyzer {
public:
    Apple8900Analyzer();
    ~Apple8900Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
