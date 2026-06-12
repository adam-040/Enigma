#pragma once

#include <ghidra/AbstractBinaryFormatAnalyzer.h>

namespace ghidra {

class CoffAnalyzer : public AbstractBinaryFormatAnalyzer {
public:
    CoffAnalyzer();
    virtual ~CoffAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
