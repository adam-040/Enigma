#pragma once
#include <ghidra/storage/Event.h>
#include <memory>
#include <vector>

namespace ghidra {
namespace storage {

class EventLog {
public:
    EventLog() = default;

    void recordEvent(std::unique_ptr<Event> event);
    bool undo(ProgramDB& program);
    bool redo(ProgramDB& program);
    bool canUndo() const { return pos_ > 0; }
    bool canRedo() const { return pos_ < events_.size(); }
    void clear();
    int getPosition() const { return pos_; }
    int getSize() const { return static_cast<int>(events_.size()); }
    const std::vector<std::unique_ptr<Event>>& getEvents() const { return events_; }

private:
    std::vector<std::unique_ptr<Event>> events_;
    int pos_ = 0;
};

} // namespace storage
} // namespace ghidra
