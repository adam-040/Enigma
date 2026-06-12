#pragma once

#include <string>

namespace ghidra {

class ManualEntry {
public:
    ManualEntry() = default;
    ManualEntry(const std::string& url, const std::string& description)
        : url_(url), description_(description) {}
    const std::string& getURL() const { return url_; }
    const std::string& getDescription() const { return description_; }
private:
    std::string url_;
    std::string description_;
};

} // namespace ghidra
