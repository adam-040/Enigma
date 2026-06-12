#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class iOS_FixupArmSymbolsAnalyzer : public AbstractAnalyzer {
public:
    iOS_FixupArmSymbolsAnalyzer();
    ~iOS_FixupArmSymbolsAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool getDefaultEnablement(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    bool isBoot(Program* program) const;
};

} // namespace ghidra
