/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DummySourceFileManager.h
/// \brief Dummy implementation of SourceFileManager that rejects all mutations
/// Translated from: ghidra.program.model.sourcemap.DummySourceFileManager
#pragma once

#include "ghidra/SourceFileManager.h"
#include <vector>

namespace ghidra {

class DummySourceFileManager : public SourceFileManager {
public:
    DummySourceFileManager() = default;

    SourceFile* addSourceFile(const std::string& path,
                              const std::string& compilerSpec) override;
    SourceFile* getSourceFile(const std::string& path) override;
    std::vector<SourceFile*> getSourceFiles() override;
    int getSourceFileCount() override;

    std::vector<SourceMapEntry> getSourceMapEntries(const Address& addr) override;

    SourceMapEntry addSourceMapEntry(SourceFile* sourceFile, int lineNumber,
                                     const Address& baseAddr, uint64_t length) override;

    bool intersectsSourceMapEntry(const AddressSetView& addrs) override;

    bool addSourceFile(SourceFile* sourceFile) override;
    bool removeSourceFile(SourceFile* sourceFile) override;
    bool containsSourceFile(SourceFile* sourceFile) override;

    std::vector<SourceFile*> getAllSourceFiles() override;
    std::vector<SourceFile*> getMappedSourceFiles() override;

    void transferSourceMapEntries(SourceFile* source, SourceFile* target) override;

    SourceMapEntryIterator getSourceMapEntryIterator(const Address& address,
                                                     bool forward) override;

    std::vector<SourceMapEntry> getSourceMapEntries(SourceFile* sourceFile,
                                                    int minLine, int maxLine) override;

    bool removeSourceMapEntry(const SourceMapEntry& entry) override;
};

} // namespace ghidra
