#include <ghidra/AnalysisScheduler.h>
#include <ghidra/AutoAnalysisManager.h>

namespace ghidra {

AnalysisScheduler::AnalysisScheduler(AutoAnalysisManager* mgr, std::unique_ptr<Analyzer> analyzer)
    : mgr_(mgr), analyzer_(std::move(analyzer)) {
    try {
        defaultEnablement_ = getDefaultEnablement();
    } catch (...) {
        defaultEnablement_ = false;
    }
    enabled_ = defaultEnablement_;
}

bool AnalysisScheduler::getDefaultEnablement() {
    Program* program = mgr_->getProgram();
    return analyzer_->getDefaultEnablement(program);
}

void AnalysisScheduler::schedule() {
    if (!scheduled_ && (!addSet_.isEmpty() || !removeSet_.isEmpty())) {
        mgr_->scheduleTask(this);
        scheduled_ = true;
    }
}

void AnalysisScheduler::added(const AddressSetView& set) {
    if (!enabled_) return;
    addSet_.add(set);
    schedule();
}

void AnalysisScheduler::added(Address addr) {
    if (!enabled_) return;
    addSet_.add(addr);
    schedule();
}

void AnalysisScheduler::removed(const AddressSetView& set) {
    if (!enabled_) return;
    removeSet_.add(set);
    schedule();
}

void AnalysisScheduler::removed(Address addr) {
    if (!enabled_) return;
    removeSet_.add(addr);
    schedule();
}

bool AnalysisScheduler::runAnalyzer(Program* program, TaskMonitor* monitor, MessageLog& log) {
    AddressSet saveAddSet;
    AddressSet saveRemoveSet;

    {
        saveAddSet = std::move(addSet_);
        saveRemoveSet = std::move(removeSet_);
        addSet_ = AddressSet();
        removeSet_ = AddressSet();
        scheduled_ = false;
    }

    if (monitor) {
        monitor->setMessage(analyzer_->getName());
        monitor->setProgress(0);
    }

    bool result = false;
    try {
        if (!saveAddSet.isEmpty()) {
            result |= analyzer_->added(program, saveAddSet, monitor, log);
        }
        if (!saveRemoveSet.isEmpty()) {
            result |= analyzer_->removed(program, saveRemoveSet, monitor, log);
        }
    } catch (const std::exception& e) {
        log.append(analyzer_->getName(), "Analyzer failed with exception: " + std::string(e.what()));
    } catch (...) {
        log.append(analyzer_->getName(), "Analyzer failed with unknown exception.");
    }
    return result;
}

void AnalysisScheduler::runCanceled() {
    addSet_ = AddressSet();
    removeSet_ = AddressSet();
    scheduled_ = false;
}

void AnalysisScheduler::optionsChanged(Options& options) {
    if (options.hasOption(analyzer_->getName())) {
        enabled_ = options.getBool(analyzer_->getName());
    } else {
        enabled_ = defaultEnablement_;
    }
    analyzer_->optionsChanged(options, mgr_->getProgram());
}

void AnalysisScheduler::registerOptions(Options& options) {
    options.registerBool(analyzer_->getName(), defaultEnablement_, analyzer_->getDescription());
}

} // namespace ghidra
