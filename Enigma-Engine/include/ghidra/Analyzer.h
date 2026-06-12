#pragma once

#include <ghidra/Program.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <ghidra/Options.h>
#include <string>

namespace ghidra {

class AnalysisOptionsUpdater;

enum class AnalyzerType {
    BYTE_ANALYZER,
    INSTRUCTION_ANALYZER,
    FUNCTION_ANALYZER,
    FUNCTION_MODIFIERS_ANALYZER,
    FUNCTION_SIGNATURES_ANALYZER,
    DATA_ANALYZER
};

std::string analyzerTypeName(AnalyzerType type);
std::string analyzerTypeDescription(AnalyzerType type);

class Analyzer {
public:
    virtual ~Analyzer() = default;

    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual AnalyzerType getAnalysisType() const = 0;

    virtual bool supportsOneTimeAnalysis() const { return false; }
    virtual bool getDefaultEnablement(Program* program) const { return true; }
    virtual AnalysisPriority getPriority() const { return AnalysisPriority::LOW_PRIORITY; }

    virtual bool canAnalyze(Program* program) const = 0;

    virtual bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) = 0;
    virtual bool removed(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) { return false; }

    virtual void registerOptions(Options& options, Program* program) {}
    virtual void optionsChanged(Options& options, Program* program) {}
    virtual AnalysisOptionsUpdater* getOptionsUpdater() { return nullptr; }

    virtual void analysisEnded(Program* program) {}

    virtual bool isPrototype() const { return false; }
};

} // namespace ghidra
