#pragma once

#include <ghidra/ChangeSet.h>
#include <cstdint>
#include <vector>

namespace ghidra {

class ProgramTreeChangeSet : public ChangeSet {
public:
    ~ProgramTreeChangeSet() override = default;

    virtual void programTreeChanged(long long id) = 0;
    virtual void programTreeAdded(long long id) = 0;
    virtual std::vector<long long> getProgramTreeChanges() = 0;
    virtual std::vector<long long> getProgramTreeAdditions() = 0;
};

} // namespace ghidra
