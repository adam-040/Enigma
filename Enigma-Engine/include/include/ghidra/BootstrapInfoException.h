#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

class BootstrapInfoException : public std::runtime_error {
public:
    BootstrapInfoException() : std::runtime_error("") {}

    explicit BootstrapInfoException(const std::string& message) : std::runtime_error(message) {}

    BootstrapInfoException(const std::string& message, const std::exception& cause)
        : std::runtime_error(message + " (caused by: " + std::string(cause.what()) + ")") {}
};

} // namespace ghidra
