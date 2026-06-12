#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class MachoConstructorDestructorAnalyzer : public AbstractAnalyzer {
public:
    MachoConstructorDestructorAnalyzer();
    ~MachoConstructorDestructorAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;

private:
    bool hasConstructorOrDestructorBlocks(Program* program) const;
};

} // namespace ghidra
