/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DummySourceFileManager.cpp
/// \brief Dummy implementation of SourceFileManager
#include "ghidra/DummySourceFileManager.h"
#include <stdexcept>

namespace ghidra {

SourceFile* DummySourceFileManager::addSourceFile(const std::string& path,
                                                  const std::string& compilerSpec) {
    throw std::runtime_error("Cannot add source files with this manager");
}

SourceFile* DummySourceFileManager::getSourceFile(const std::string& path) {
    return nullptr;
}

std::vector<SourceFile*> DummySourceFileManager::getSourceFiles() {
    return {};
}

int DummySourceFileManager::getSourceFileCount() {
    return 0;
}

std::vector<SourceMapEntry> DummySourceFileManager::getSourceMapEntries(const Address& addr) {
    return {};
}

SourceMapEntry DummySourceFileManager::addSourceMapEntry(SourceFile* sourceFile, int lineNumber,
                                                          const Address& baseAddr,
                                                          uint64_t length) {
    throw std::runtime_error("Cannot add source map entries with this manager");
}

bool DummySourceFileManager::intersectsSourceMapEntry(const AddressSetView& addrs) {
    return false;
}

bool DummySourceFileManager::addSourceFile(SourceFile* sourceFile) {
    throw std::runtime_error("cannot add source files to this manager");
}

bool DummySourceFileManager::removeSourceFile(SourceFile* sourceFile) {
    throw std::runtime_error("cannot remove source files from this manager");
}

bool DummySourceFileManager::containsSourceFile(SourceFile* sourceFile) {
    return false;
}

std::vector<SourceFile*> DummySourceFileManager::getAllSourceFiles() {
    return {};
}

std::vector<SourceFile*> DummySourceFileManager::getMappedSourceFiles() {
    return {};
}

void DummySourceFileManager::transferSourceMapEntries(SourceFile* source, SourceFile* target) {
    throw std::runtime_error("Dummy source file manager cannot transfer map info");
}

SourceMapEntryIterator DummySourceFileManager::getSourceMapEntryIterator(const Address& address,
                                                                          bool forward) {
    return SourceMapEntryIterator();
}

std::vector<SourceMapEntry> DummySourceFileManager::getSourceMapEntries(SourceFile* sourceFile,
                                                                         int minLine,
                                                                         int maxLine) {
    return {};
}

bool DummySourceFileManager::removeSourceMapEntry(const SourceMapEntry& entry) {
    throw std::runtime_error("cannot remove source map entries from this manager");
}

} // namespace ghidra
