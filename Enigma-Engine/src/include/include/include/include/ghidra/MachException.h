#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class MachException : public std::exception {
private:
    std::string message_;

public:
    explicit MachException(const std::string& message) : message_(message) {}

    explicit MachException(const std::exception& cause) : message_(cause.what()) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
