#include <ghidra/storage/EventLog.h>

namespace ghidra {
namespace storage {

void EventLog::recordEvent(std::unique_ptr<Event> event) {
    if (pos_ < static_cast<int>(events_.size())) {
        events_.resize(pos_);
    }
    events_.push_back(std::move(event));
    pos_ = static_cast<int>(events_.size());
}

bool EventLog::undo(ProgramDB& program) {
    if (pos_ == 0) return false;
    pos_--;
    events_[pos_]->undo(program);
    return true;
}

bool EventLog::redo(ProgramDB& program) {
    if (pos_ >= static_cast<int>(events_.size())) return false;
    events_[pos_]->redo(program);
    pos_++;
    return true;
}

void EventLog::clear() {
    events_.clear();
    pos_ = 0;
}

} // namespace storage
} // namespace ghidra
