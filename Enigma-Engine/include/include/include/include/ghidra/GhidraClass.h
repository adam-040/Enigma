#pragma once
#include <ghidra/Namespace.h>

namespace ghidra {

class GhidraClass : public Namespace {
public:
    GhidraClass() = default;
    GhidraClass(const std::string& name, Namespace* parent = nullptr, long id = -1)
        : Namespace(name, parent, id) {}
};

} // namespace ghidra
