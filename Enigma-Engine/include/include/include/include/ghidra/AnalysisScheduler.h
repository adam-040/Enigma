#pragma once

#include <ghidra/Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <memory>

namespace ghidra {

class AutoAnalysisManager;

class AnalysisScheduler {
public:
    AnalysisScheduler(AutoAnalysisManager* mgr, std::unique_ptr<Analyzer> analyzer);

    Analyzer* getAnalyzer() const { return analyzer_.get(); }
    std::string getName() const { return analyzer_->getName(); }
    int getPriorityValue() const { return analyzer_->getPriority().priority(); }

    void added(const AddressSetView& set);
    void added(Address addr);
    void removed(const AddressSetView& set);
    void removed(Address addr);

    void schedule();
    void runCanceled();

    bool runAnalyzer(Program* program, TaskMonitor* monitor, MessageLog& log);

    void optionsChanged(Options& options);
    void registerOptions(Options& options);

private:
    AutoAnalysisManager* mgr_;
    std::unique_ptr<Analyzer> analyzer_;
    AddressSet addSet_;
    AddressSet removeSet_;
    bool defaultEnablement_ = false;
    bool enabled_ = true;
    bool scheduled_ = false;

    bool getDefaultEnablement();
};

} // namespace ghidra
