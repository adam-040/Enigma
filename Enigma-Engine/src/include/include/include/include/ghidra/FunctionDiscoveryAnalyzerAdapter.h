#pragma once

#include <ghidra/Analyzer.h>
#include <ghidra/FunctionDiscoveryAnalyzer.h>
#include <ghidra/BinaryLoader.h>

namespace ghidra {

class FunctionDiscoveryAnalyzerAdapter : public Analyzer {
public:
    explicit FunctionDiscoveryAnalyzerAdapter(BinaryLoader* loader = nullptr, FunctionDiscoveryOptions options = {});
    ~FunctionDiscoveryAnalyzerAdapter() override = default;

    std::string getName() const override { return "Function Discovery"; }
    std::string getDescription() const override { return "Discovers functions from loader entry points, exports, symbols, and imports."; }
    AnalyzerType getAnalysisType() const override { return AnalyzerType::FUNCTION_ANALYZER; }

    bool canAnalyze(Program* program) const override { return program != nullptr; }
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

    void setLoader(BinaryLoader* loader) { loader_ = loader; }

private:
    BinaryLoader* loader_;
    FunctionDiscoveryOptions options_;
};

} // namespace ghidra
