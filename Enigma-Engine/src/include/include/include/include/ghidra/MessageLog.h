#pragma once

#include <string>
#include <sstream>

namespace ghidra {

class MessageLog {
    std::ostringstream log_;
public:
    MessageLog() = default;

    void append(const std::string& msg) { log_ << msg << "\n"; }
    void append(const std::string& msg, const std::string& detail) { log_ << msg << ": " << detail << "\n"; }

    std::string toString() const { return log_.str(); }
    bool isEmpty() const { return log_.str().empty(); }
    void clear() { log_.str(""); }
};

} // namespace ghidra
