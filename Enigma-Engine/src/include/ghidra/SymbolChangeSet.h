#pragma once

#include <ghidra/ChangeSet.h>
#include <cstdint>
#include <vector>

namespace ghidra {

class SymbolChangeSet : public ChangeSet {
public:
    ~SymbolChangeSet() override = default;

    virtual void symbolChanged(long long id) = 0;
    virtual void symbolAdded(long long id) = 0;
    virtual std::vector<long long> getSymbolChanges() = 0;
    virtual std::vector<long long> getSymbolAdditions() = 0;
};

} // namespace ghidra
