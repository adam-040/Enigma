#pragma once

#include <string>

namespace ghidra {

class SleighDebugLogger {
public:
    enum class Mode { NONE, BRIEF, DETAILED };

    SleighDebugLogger() = default;
    explicit SleighDebugLogger(Mode mode) : mode_(mode) {}

    Mode getMode() const { return mode_; }
    void setMode(Mode mode) { mode_ = mode; }

    void log(const std::string& message) const {
        if (mode_ != Mode::NONE) {
            // Stub: no actual logging
        }
    }

private:
    Mode mode_ = Mode::NONE;
};

} // namespace ghidra
