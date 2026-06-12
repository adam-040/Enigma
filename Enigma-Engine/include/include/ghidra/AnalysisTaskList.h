#pragma once

#include <ghidra/AnalysisScheduler.h>
#include <vector>
#include <memory>
#include <algorithm>

namespace ghidra {

class AutoAnalysisManager;

class AnalysisTaskList {
public:
    AnalysisTaskList(AutoAnalysisManager* mgr, const std::string& name);

    void clear();
    void add(std::unique_ptr<Analyzer> analyzer);

    void notifyAdded(const AddressSetView& set);
    void notifyAdded(Address addr);
    void notifyRemoved(const AddressSetView& set);
    void notifyRemoved(Address addr);
    void notifyResume();

    void optionsChanged(Options& options);
    void registerOptions(Options& options);
    void notifyAnalysisEnded(Program* program);

    const std::vector<std::unique_ptr<AnalysisScheduler>>& getSchedulers() const { return schedulers_; }

private:
    AutoAnalysisManager* mgr_;
    std::string name_;
    std::vector<std::unique_ptr<AnalysisScheduler>> schedulers_;
};

} // namespace ghidra
