#pragma once

#include <ghidra/Address.h>
#include <string>

namespace ghidra {

class VariableOffset {
public:
    VariableOffset() = default;
    VariableOffset(const Address& addr, const std::string& name)
        : address_(addr), name_(name) {}

    const Address& getAddress() const { return address_; }
    const std::string& getName() const { return name_; }
    bool isStackRelative() const { return stackRelative_; }
    void setStackRelative(bool v) { stackRelative_ = v; }

private:
    Address address_;
    std::string name_;
    bool stackRelative_ = false;
};

} // namespace ghidra
