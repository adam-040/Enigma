#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class GolangStringAnalyzer : public AbstractAnalyzer {
public:
    GolangStringAnalyzer();
    virtual ~GolangStringAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    bool markupSliceStructsOption_ = true;
    bool markupDataSegmentStructsOption_ = true;
};

} // namespace ghidra
