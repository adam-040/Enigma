#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class StringsAnalyzer : public AbstractAnalyzer {
public:
    StringsAnalyzer();
    ~StringsAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
