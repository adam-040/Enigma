#pragma once

#include <ghidra/FileBasedDataTypeManager.h>

namespace ghidra {

class DomainFileBasedDataTypeManager : public virtual FileBasedDataTypeManager {
public:
    virtual class DomainFile* getDomainFile() = 0;
};

} // namespace ghidra
