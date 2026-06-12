#pragma once

#include <ghidra/Analyzer.h>

namespace ghidra {

class ImportThunkAnalyzer : public Analyzer {
public:
    ImportThunkAnalyzer() = default;
    ~ImportThunkAnalyzer() override = default;

    std::string getName() const override { return "Import Thunk"; }
    std::string getDescription() const override { return "Identifies thunks that jump directly to imported functions and renames/marks them."; }
    AnalyzerType getAnalysisType() const override { return AnalyzerType::FUNCTION_ANALYZER; }

    bool canAnalyze(Program* program) const override { return program != nullptr; }
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
