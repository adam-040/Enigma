#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class X86FunctionPurgeAnalyzer : public AbstractAnalyzer {
public:
    X86FunctionPurgeAnalyzer();
    virtual ~X86FunctionPurgeAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
