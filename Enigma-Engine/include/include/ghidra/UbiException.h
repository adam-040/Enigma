#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class UbiException : public std::exception {
private:
    std::string message_;

public:
    explicit UbiException(const std::string& message) : message_(message) {}

    explicit UbiException(const std::exception& cause) : message_(cause.what()) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
