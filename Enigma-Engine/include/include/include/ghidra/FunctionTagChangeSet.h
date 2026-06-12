#pragma once

#include <ghidra/ChangeSet.h>
#include <cstdint>
#include <vector>

namespace ghidra {

class FunctionTagChangeSet : public ChangeSet {
public:
    ~FunctionTagChangeSet() override = default;

    virtual void tagChanged(long long id) = 0;
    virtual void tagCreated(long long id) = 0;
    virtual std::vector<long long> getTagChanges() = 0;
    virtual std::vector<long long> getTagCreations() = 0;
};

} // namespace ghidra
