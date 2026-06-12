#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class DWARFLineException : public std::runtime_error {
public:
    DWARFLineException() : std::runtime_error("") {}

    explicit DWARFLineException(const std::string& message) : std::runtime_error(message) {}

    DWARFLineException(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
