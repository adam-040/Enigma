#pragma once

#include <ghidra/Analyzer.h>
#include <ghidra/AddressSet.h>
#include <vector>

namespace ghidra {

class AbstractAnalyzer : public Analyzer {
protected:
    std::string name_;
    std::string description_;
    AnalyzerType type_;
    bool defaultEnablement_ = false;
    bool supportsOneTimeAnalysis_ = false;
    bool isPrototype_ = false;
    AnalysisPriority priority_ = AnalysisPriority::LOW_PRIORITY;

    static const AddressSet EMPTY_ADDRESS_SET;

public:
    AbstractAnalyzer(const std::string& name, const std::string& description, AnalyzerType type);
    ~AbstractAnalyzer() override = default;

    std::string getName() const final { return name_; }
    std::string getDescription() const final { return description_.empty() ? "No Description" : description_; }
    AnalyzerType getAnalysisType() const final { return type_; }

    bool supportsOneTimeAnalysis() const final { return supportsOneTimeAnalysis_; }
    bool getDefaultEnablement(Program* program) const override { return defaultEnablement_; }
    AnalysisPriority getPriority() const final { return priority_; }

    bool canAnalyze(Program* program) const override { return program != nullptr; }

    bool removed(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override { return false; }
    void registerOptions(Options& options, Program* program) override {}
    void optionsChanged(Options& options, Program* program) override {}
    void analysisEnded(Program* program) override {}
    bool isPrototype() const final { return isPrototype_; }

    virtual AddressSetView* analyzeLocation(Program* program, const Address& location,
                                            const AddressSetView& set, TaskMonitor* monitor);

    AnalysisOptionsUpdater* getOptionsUpdater() override { return nullptr; }

protected:
    void setPriority(const AnalysisPriority& priority) { priority_ = priority; }
    void setDefaultEnablement(bool b) { defaultEnablement_ = b; }
    void setSupportsOneTimeAnalysis(bool b = true) { supportsOneTimeAnalysis_ = b; }
    void setPrototype(bool b = true) { isPrototype_ = b; }

    AddressSetView* runParallelAddressAnalysis(Program* program,
                                               const std::vector<Address>& addresses,
                                               const AddressSetView& set,
                                               int threadCount,
                                               TaskMonitor* monitor);
};

} // namespace ghidra
