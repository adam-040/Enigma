#include <ghidra/AnalysisTaskList.h>

namespace ghidra {

AnalysisTaskList::AnalysisTaskList(AutoAnalysisManager* mgr, const std::string& name)
    : mgr_(mgr), name_(name) {}

void AnalysisTaskList::clear() {
    schedulers_.clear();
}

void AnalysisTaskList::add(std::unique_ptr<Analyzer> analyzer) {
    auto scheduler = std::make_unique<AnalysisScheduler>(mgr_, std::move(analyzer));
    int newPriority = scheduler->getPriorityValue();
    size_t insertPos = 0;
    for (size_t i = 0; i < schedulers_.size(); ++i) {
        int existingPriority = schedulers_[i]->getPriorityValue();
        if (existingPriority > newPriority) {
            insertPos = i + 1;
        } else {
            break;
        }
    }
    bool inserted = false;
    for (size_t i = 0; i < schedulers_.size(); ++i) {
        if (schedulers_[i]->getPriorityValue() > newPriority) {
            schedulers_.insert(schedulers_.begin() + i, std::move(scheduler));
            inserted = true;
            break;
        }
    }
    if (!inserted) {
        schedulers_.push_back(std::move(scheduler));
    }
}

void AnalysisTaskList::notifyAdded(const AddressSetView& set) {
    for (auto& s : schedulers_) {
        s->added(set);
    }
}

void AnalysisTaskList::notifyAdded(Address addr) {
    for (auto& s : schedulers_) {
        s->added(addr);
    }
}

void AnalysisTaskList::notifyRemoved(const AddressSetView& set) {
    for (auto& s : schedulers_) {
        s->removed(set);
    }
}

void AnalysisTaskList::notifyRemoved(Address addr) {
    for (auto& s : schedulers_) {
        s->removed(addr);
    }
}

void AnalysisTaskList::notifyResume() {
    for (auto& s : schedulers_) {
        s->schedule();
    }
}

void AnalysisTaskList::optionsChanged(Options& options) {
    for (auto& s : schedulers_) {
        s->optionsChanged(options);
    }
}

void AnalysisTaskList::registerOptions(Options& options) {
    for (auto& s : schedulers_) {
        s->registerOptions(options);
    }
}

void AnalysisTaskList::notifyAnalysisEnded(Program* program) {
    for (auto& s : schedulers_) {
        s->getAnalyzer()->analysisEnded(program);
    }
}

} // namespace ghidra
