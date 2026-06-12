#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class EmbeddedMediaAnalyzer : public AbstractAnalyzer {
public:
    EmbeddedMediaAnalyzer();
    virtual ~EmbeddedMediaAnalyzer() = default;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

    virtual void registerOptions(Options& options, Program* program) override;
    virtual void optionsChanged(Options& options, Program* program) override;

private:
    bool createBookmarksEnabled_ = true;
};

} // namespace ghidra
