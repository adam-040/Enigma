#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class AggressiveInstructionFinderAnalyzer : public AbstractAnalyzer {
    bool createBookmarksEnabled_ = true;

public:
    AggressiveInstructionFinderAnalyzer();
    virtual ~AggressiveInstructionFinderAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;
};

} // namespace ghidra
