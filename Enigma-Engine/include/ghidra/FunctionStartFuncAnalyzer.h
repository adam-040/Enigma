#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class FunctionStartFuncAnalyzer : public AbstractAnalyzer {
public:
    FunctionStartFuncAnalyzer();
    virtual ~FunctionStartFuncAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
