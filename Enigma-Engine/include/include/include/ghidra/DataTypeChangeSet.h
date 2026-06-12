#pragma once

#include <ghidra/ChangeSet.h>
#include <cstdint>
#include <vector>

namespace ghidra {

class DataTypeChangeSet : public ChangeSet {
public:
    ~DataTypeChangeSet() override = default;

    virtual void dataTypeChanged(long long id) = 0;
    virtual void dataTypeAdded(long long id) = 0;
    virtual std::vector<long long> getDataTypeChanges() = 0;
    virtual std::vector<long long> getDataTypeAdditions() = 0;

    virtual void categoryChanged(long long id) = 0;
    virtual void categoryAdded(long long id) = 0;
    virtual std::vector<long long> getCategoryChanges() = 0;
    virtual std::vector<long long> getCategoryAdditions() = 0;

    virtual void sourceArchiveChanged(long long id) = 0;
    virtual void sourceArchiveAdded(long long id) = 0;
    virtual std::vector<long long> getSourceArchiveChanges() = 0;
    virtual std::vector<long long> getSourceArchiveAdditions() = 0;
};

} // namespace ghidra
