#pragma once

#include <ghidra/AbstractBinaryFormatAnalyzer.h>

namespace ghidra {

class MachoAnalyzer : public AbstractBinaryFormatAnalyzer {
public:
    MachoAnalyzer();
    virtual ~MachoAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
