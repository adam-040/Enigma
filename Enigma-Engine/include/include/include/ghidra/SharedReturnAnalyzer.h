#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class SharedReturnAnalyzer : public AbstractAnalyzer {
public:
    SharedReturnAnalyzer();
    ~SharedReturnAnalyzer() override = default;

protected:
    SharedReturnAnalyzer(const std::string& name, const std::string& description, AnalyzerType type);

public:
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    bool assumeContiguousFunctions_ = true;
    bool considerConditionalBranches_ = false;
};

} // namespace ghidra
