#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class ApplyDataArchiveAnalyzer : public AbstractAnalyzer {
public:
    ApplyDataArchiveAnalyzer();
    virtual ~ApplyDataArchiveAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;

private:
    bool createBookmarksEnabled_ = true;
    std::string archiveChooser_ = "[Auto-Detect]";
};

} // namespace ghidra
