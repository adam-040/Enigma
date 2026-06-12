#pragma once

#include <string>

namespace ghidra {

class Processor {
public:
    Processor() = default;
    explicit Processor(const std::string& name) : name_(name) {}
    const std::string& getName() const { return name_; }
    bool operator==(const Processor& other) const { return name_ == other.name_; }
    bool operator!=(const Processor& other) const { return !(*this == other); }
private:
    std::string name_;
};

} // namespace ghidra
