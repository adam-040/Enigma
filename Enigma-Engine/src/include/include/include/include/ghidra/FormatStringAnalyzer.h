#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class FormatStringAnalyzer : public AbstractAnalyzer {
public:
    FormatStringAnalyzer();
    virtual ~FormatStringAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    bool createBookmarksEnabled_ = false;
};

} // namespace ghidra
