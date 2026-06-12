#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class NewExt4Analyzer : public AbstractAnalyzer {
public:
    NewExt4Analyzer();
    ~NewExt4Analyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
};

} // namespace ghidra
