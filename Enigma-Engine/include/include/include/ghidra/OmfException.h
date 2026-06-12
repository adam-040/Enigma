#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class OmfException : public std::exception {
private:
    std::string message_;

public:
    explicit OmfException(const std::string& message) : message_(message) {}

    const char* what() const noexcept override { return message_.c_str(); }
};

} // namespace ghidra
