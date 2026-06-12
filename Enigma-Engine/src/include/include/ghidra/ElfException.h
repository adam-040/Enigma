#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class ElfException : public std::exception {
private:
    std::string message_;

public:
    explicit ElfException(const std::string& message) : message_(message) {}

    explicit ElfException(const std::exception& cause) : message_(cause.what()) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
