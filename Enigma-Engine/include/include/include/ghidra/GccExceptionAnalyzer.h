#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <set>

namespace ghidra {

class GccExceptionAnalyzer : public AbstractAnalyzer {
public:
    GccExceptionAnalyzer();
    virtual ~GccExceptionAnalyzer() = default;

    virtual bool canAnalyze(Program* program) const override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    bool createTryCatchCommentsEnabled_ = true;
    std::set<Program*> visitedPrograms_;
};

} // namespace ghidra
