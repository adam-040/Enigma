#pragma once

#include <string>
#include <vector>

namespace ghidra {

class ContextSymbol {
public:
    ContextSymbol() = default;
    ContextSymbol(const std::string& name, int offset, int size)
        : name_(name), offset_(offset), size_(size) {}

    const std::string& getName() const { return name_; }
    int getOffset() const { return offset_; }
    int getSize() const { return size_; }

private:
    std::string name_;
    int offset_ = 0;
    int size_ = 0;
};

} // namespace ghidra
