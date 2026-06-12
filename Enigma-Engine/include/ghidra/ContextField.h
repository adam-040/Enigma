#pragma once

#include <string>

namespace ghidra {

class ContextField {
public:
    ContextField() = default;
    ContextField(const std::string& name, int startBit, int numBits)
        : name_(name), startBit_(startBit), numBits_(numBits) {}

    const std::string& getName() const { return name_; }
    int getStartBit() const { return startBit_; }
    int getNumBits() const { return numBits_; }

private:
    std::string name_;
    int startBit_ = 0;
    int numBits_ = 0;
};

} // namespace ghidra
