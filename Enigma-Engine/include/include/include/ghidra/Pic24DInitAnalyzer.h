#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class Pic24DInitAnalyzer : public AbstractAnalyzer {
public:
    Pic24DInitAnalyzer();
    ~Pic24DInitAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
