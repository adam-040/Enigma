#pragma once

#include <ghidra/DataTypeManager.h>
#include <string>

namespace ghidra {

class FileBasedDataTypeManager : public virtual DataTypeManager {
public:
    virtual std::string getPath() = 0;
};

} // namespace ghidra
