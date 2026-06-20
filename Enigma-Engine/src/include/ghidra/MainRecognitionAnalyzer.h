#pragma once
/// \file MainRecognitionAnalyzer.h
/// \brief Post-analysis pass that identifies the user's main() or WinMain()
/// function by walking the call graph from the program entry point through
/// known CRT startup wrappers.
///
/// The algorithm (derived from crt_classification_snippet.cpp):
///   1. Find the "entry" function (executable entry point).
///   2. Walk its direct callees and collect functions that call known CRT
///      startup imports (e.g. exit, _initterm, __set_app_type …).  These are
///      classified as CRT.
///   3. Propagate: for every classified CRT function, its non-CRT callees are
///      "main candidates", scored by heuristic confidence.
///   4. The highest-confidence anonymous candidate is renamed to "main" (or
///      "WinMain" if it originates from __getmainargs / __wgetmainargs).

#include <ghidra/Analyzer.h>
#include <string>

namespace ghidra {

class MainRecognitionAnalyzer : public Analyzer {
public:
    MainRecognitionAnalyzer();
    ~MainRecognitionAnalyzer() override = default;

    std::string getName()        const override { return "Main Recognition"; }
    std::string getDescription() const override {
        return "Identifies the user's main() or WinMain() by tracing the "
               "entry-point call graph through known CRT startup functions.";
    }
    AnalyzerType getAnalysisType() const override {
        return AnalyzerType::FUNCTION_ANALYZER;
    }

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
