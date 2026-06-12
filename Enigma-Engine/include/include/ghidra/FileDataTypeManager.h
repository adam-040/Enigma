#pragma once

#include <string>
#include <ghidra/StandAloneDataTypeManager.h>
#include <ghidra/FileArchiveBasedDataTypeManager.h>

namespace ghidra {

// TODO: Stub - PackedDB-backed DataTypeManager for .gdt files
class FileDataTypeManager : public StandAloneDataTypeManager, public virtual FileArchiveBasedDataTypeManager {
public:
    FileDataTypeManager(const std::string& rootName);
    ~FileDataTypeManager() override;

    std::string getPath() override;

    ArchiveType getType();
    std::string toString() const;
};

} // namespace ghidra
