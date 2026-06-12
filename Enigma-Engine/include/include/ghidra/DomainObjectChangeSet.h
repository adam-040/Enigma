#pragma once

namespace ghidra {

class DomainObjectChangeSet {
public:
    virtual ~DomainObjectChangeSet() = default;

    virtual bool hasChanges() = 0;
};

} // namespace ghidra
