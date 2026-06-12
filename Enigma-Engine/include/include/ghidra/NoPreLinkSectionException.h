#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class NoPreLinkSectionException : public std::exception {
private:
    std::string message_;

public:
    explicit NoPreLinkSectionException(const std::string& message) : message_(message) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
