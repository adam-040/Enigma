#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <unordered_set>
#include <string>

namespace ghidra {

class NoReturnFunctionAnalyzer : public AbstractAnalyzer {
public:
    NoReturnFunctionAnalyzer();
    ~NoReturnFunctionAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    void markNoReturn(Program* program, const std::string& name, TaskMonitor* monitor, MessageLog& log);

    std::unordered_set<std::string> functionNames_;
    std::unordered_set<std::string> wildcardFunctionNames_;
    bool createBookmarksEnabled_ = true;

    static std::unordered_set<std::string> defaultNoReturnNames();
};

} // namespace ghidra
