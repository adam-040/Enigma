#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class MipsSymbolAnalyzer : public AbstractAnalyzer {
public:
    MipsSymbolAnalyzer();
    ~MipsSymbolAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
    void analysisEnded(Program* program) override;
};

} // namespace ghidra
