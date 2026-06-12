#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class DWARFAnalyzer : public AbstractAnalyzer {
public:
    DWARFAnalyzer();
    virtual ~DWARFAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual bool getDefaultEnablement(Program* program) const override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
};

} // namespace ghidra
