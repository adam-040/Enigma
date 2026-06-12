#include "ghidra/FileDataTypeManager.h"

namespace ghidra {

FileDataTypeManager::FileDataTypeManager(const std::string& rootName)
    : StandAloneDataTypeManager(rootName) {
}

FileDataTypeManager::~FileDataTypeManager() = default;

std::string FileDataTypeManager::getPath() {
    return "";
}

ArchiveType FileDataTypeManager::getType() {
    return ArchiveType::FILE;
}

std::string FileDataTypeManager::toString() const {
    return "FileDataTypeManager - " + StandAloneDataTypeManager::getName();
}

} // namespace ghidra
