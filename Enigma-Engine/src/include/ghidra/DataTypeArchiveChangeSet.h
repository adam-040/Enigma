#pragma once

#include <ghidra/DomainObjectChangeSet.h>
#include <ghidra/DataTypeChangeSet.h>

namespace ghidra {

class DataTypeArchiveChangeSet : public DomainObjectChangeSet, public DataTypeChangeSet {
public:
    ~DataTypeArchiveChangeSet() override = default;
};

} // namespace ghidra
