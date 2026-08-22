/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BinaryLoader.h
/// \brief Adapter interface for binary loading (LIEF-based)
/// Bridges LIEF binary parsing to Enigma Engine Program Model
#pragma once

#include <ghidra/Address.h>
#include <ghidra/MemoryBlockType.h>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

class ProgramDB;
class AddressFactory;
class Memory;

struct SectionInfo {
    std::string name;
    uint64_t virtualAddress;
    uint64_t virtualSize;
    uint64_t fileOffset;
    uint64_t fileSize;
    uint32_t type;
    bool isReadable;
    bool isWritable;
    bool isExecutable;
    uint32_t reserved1 = 0; // Mach-O: indirect sym table index / section ordinal
    uint32_t reserved2 = 0; // Mach-O: stub size / alignment
};

struct SymbolInfo {
    std::string name;
    uint64_t address;
    uint64_t size;
    bool isFunction;
    bool isExternal;
};

struct ImportInfo {
    std::string libraryName;
    std::string functionName;
    uint64_t address;
};

struct ExportInfo {
    std::string name;
    uint64_t address;
    // True when the export's function RVA points inside the export directory:
    // the bytes there are an ASCII "DLLName.SymbolName" forwarder string.
    bool isForwarder = false;
    std::string forwarderString;
    // Name of the exporting DLL (export directory Name RVA), used as the
    // thunk's library namespace. Empty when the PE omits the name.
    std::string dllName;
};

struct DelayLoadInfo {
    std::string name;
    std::string libraryName;
    uint64_t address;
};

// One dylib entry from a dyld shared cache image table
// (dyld_cache_image_info).  address is the cache-relative vm address,
// fileOffset is the offset of the embedded Mach-O within the cache file.
struct DyldCacheImageInfo {
    std::string name;
    uint64_t address;
    uint64_t fileOffset;
};

struct RelocationInfo {
    uint64_t address;
    int64_t type;
    std::string symbolName;
    std::string libraryName;
};

class BinaryLoader {
public:
    virtual ~BinaryLoader() = default;

    virtual bool load(const std::string& filePath) = 0;

    virtual std::string getFormatName() const = 0;
    virtual std::string getArchitecture() const = 0;
    virtual int getBitness() const = 0;
    virtual bool isBigEndian() const = 0;

    virtual uint64_t getEntryPoint() const = 0;
    virtual uint64_t getImageBase() const = 0;

    virtual std::vector<SectionInfo> getSections() const = 0;
    virtual std::vector<SymbolInfo> getSymbols() const = 0;
    virtual std::vector<ImportInfo> getImports() const = 0;
    virtual std::vector<ExportInfo> getExports() const = 0;
    virtual std::vector<DelayLoadInfo> getDelayLoads() const = 0;
    virtual std::vector<RelocationInfo> getRelocations() const = 0;

    virtual std::vector<uint8_t> getBytes(uint64_t address, size_t size) const = 0;
    virtual std::vector<uint8_t> getRawDataCopy() const = 0;
    virtual uint64_t virtualAddressToFileOffset(uint64_t vaddr) const = 0;
    virtual bool populateProgram(ProgramDB* program) = 0;

    // True when the loaded file is a dyld shared cache (GP-7079).
    virtual bool isDyldCache() const { return false; }
    // Dylibs listed in the cache's image table.
    virtual std::vector<DyldCacheImageInfo> getDyldCacheImages() const { return {}; }
    // Re-parse the cache as the named dylib: its embedded Mach-O replaces the
    // cache's sections/symbols/imports so analysis targets a single image.
    virtual bool loadDyldCacheImage(const std::string& name) { (void)name; return false; }

    static std::string guessLanguageFromArch(const std::string& arch, int bitness, bool bigEndian = false);
    static std::string guessCompilerSpecFromArch(const std::string& arch, int bitness);

protected:
    static MemoryBlockType sectionToMemoryBlockType(const SectionInfo& section);
};

std::unique_ptr<BinaryLoader> createLoader();

} // namespace ghidra
