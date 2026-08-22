/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BinaryLoader.cpp
/// \brief Binary loader adapter implementation - PE/ELF parsing
#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/Memory.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ExternalManager.h"
#include "ghidra/Namespace.h"
#include "ghidra/Msg.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/LanguageID.h"
#include "ghidra/CompilerSpecID.h"

#include <algorithm>
#include <fstream>
#include <cstring>
#include <limits>
#include <sstream>

namespace ghidra {

MemoryBlockType BinaryLoader::sectionToMemoryBlockType(const SectionInfo& section) {
    if (section.isExecutable) return MemoryBlockType::DEFAULT;
    return MemoryBlockType::DEFAULT;
}

std::string BinaryLoader::guessLanguageFromArch(const std::string& arch, int bitness, bool bigEndian) {
    if (arch.find("x86") != std::string::npos || arch.find("i386") != std::string::npos ||
        arch.find("i686") != std::string::npos) {
        return bitness == 64 ? "x86:LE:64:default" : "x86:LE:32:default";
    }
    if (arch.find("AARCH64") != std::string::npos || arch.find("aarch64") != std::string::npos) {
        return bitness == 64 ? "AARCH64:LE:64:v8A" : "ARM:LE:32:v8";
    }
    if (arch.find("ARM") != std::string::npos || arch.find("arm") != std::string::npos) {
        if (bigEndian) return bitness == 64 ? "AARCH64:LE:64:v8A" : "ARM:BE:32:v8";
        return bitness == 64 ? "AARCH64:LE:64:v8A" : "ARM:LE:32:v8";
    }
    if (arch.find("MIPS") != std::string::npos || arch.find("mips") != std::string::npos) {
        return bitness == 64
            ? (bigEndian ? "MIPS:BE:64:default" : "MIPS:LE:64:default")
            : (bigEndian ? "MIPS:BE:32:default" : "MIPS:LE:32:default");
    }
    if (arch.find("PowerPC") != std::string::npos || arch.find("ppc") != std::string::npos) {
        return bitness == 64
            ? (bigEndian ? "PowerPC:BE:64:default" : "PowerPC:LE:64:64-32addr")
            : (bigEndian ? "PowerPC:BE:32:default" : "PowerPC:LE:32:default");
    }
    if (arch.find("RISCV") != std::string::npos || arch.find("riscv") != std::string::npos) {
        return bitness == 64 ? "RISCV:LE:64:default" : "RISCV:LE:32:default";
    }
    return "unknown";
}

std::string BinaryLoader::guessCompilerSpecFromArch(const std::string& arch, int bitness) {
    if (arch.find("x86") != std::string::npos || arch.find("i386") != std::string::npos) {
        return bitness == 64 ? "windows" : "windows";
    }
    return "default";
}

class SimplePELoader : public BinaryLoader {
public:
    bool load(const std::string& filePath) override {
        reset();

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return false;

        file.seekg(0, std::ios::end);
        fileSize_ = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);

        rawData_.resize(fileSize_);
        file.read(reinterpret_cast<char*>(rawData_.data()), fileSize_);
        file.close();

        if (rawData_.size() < 64) return false;

        if (rawData_[0] == 'M' && rawData_[1] == 'Z') {
            return parsePE();
        } else if (rawData_.size() >= 52 && rawData_[0] == 0x7F && rawData_[1] == 'E' &&
                   rawData_[2] == 'L' && rawData_[3] == 'F') {
            return parseELF();
        } else if (rawData_.size() >= 8) {
            uint32_t magic = *reinterpret_cast<uint32_t*>(rawData_.data());
            // MachO 32-bit: FEEDFACE (0xCEFAEDFE), 64-bit: FEEDFACF (0xCFFAEDFE)
            if (magic == 0xCEFAEDFE || magic == 0xCFFAEDFE) {
                return parseMachO();
            }
            // Fat/universal Mach-O: 0xBEBAFECA
            if (magic == 0xBEBAFECA) {
                return parseFatMachO();
            }
            // dyld shared cache: 0x646C7964 ('dyld') classic header,
            // 0x6A1A64A9 arm64e ("new") header
            if (magic == 0x646C7964 || magic == 0x6A1A64A9) {
                return parseDyldCache();
            }
        }
        if (rawData_.size() >= 8 && std::memcmp(rawData_.data(), "!<arch>\n", 8) == 0) {
            return parseCOFFArchive();
        }
        if (rawData_.size() >= 20 + 40) {
            uint16_t machine = coff16(0);
            uint16_t numSecs = coff16(2);
            uint16_t optSize = coff16(16);
            if (isCoffMachine(machine) && numSecs > 0 && numSecs < 0x100 && optSize == 0 &&
                rawData_.size() >= 20 + static_cast<uint16_t>(numSecs) * 40) {
                return parseCOFF();
            }
        }
        // Intel HEX detection: first character is ':'
        if (!rawData_.empty() && rawData_[0] == ':') {
            return parseIntelHex();
        }
        // Motorola S-Record detection: first line starts with 'S'
        if (!rawData_.empty() && rawData_[0] == 'S') {
            return parseSRecord();
        }
        return false;
    }

    std::string getFormatName() const override { return formatName_; }
    std::string getArchitecture() const override { return arch_; }
    int getBitness() const override { return bitness_; }
    bool isBigEndian() const override {
        // PPC Mach-O (cpu type 18) is big-endian; everything else is little
        if (formatName_ == "Mac OS X Mach-O") {
            // Check cpu_type from the raw data
            uint32_t cputype = 0;
            if (rawData_.size() >= 8) {
                if (rawData_.size() >= 4) {
                    uint32_t magic = *reinterpret_cast<const uint32_t*>(rawData_.data());
                    if (magic == 0xCEFAEDFE)
                        cputype = *reinterpret_cast<const uint32_t*>(rawData_.data() + 4);
                    else if (magic == 0xCFFAEDFE)
                        cputype = *reinterpret_cast<const uint32_t*>(rawData_.data() + 4);
                }
            }
            // CPU_TYPE_POWERPC = 18, CPU_TYPE_POWERPC64 = 0x01000012
            return (cputype == 0x01000012 || cputype == 18);
        }
        if (formatName_ == "ELF" && rawData_.size() >= 6) {
            // EI_DATA byte: 1 = little-endian, 2 = big-endian
            return rawData_[5] == 2;
        }
        return false;
    }
    uint64_t getEntryPoint() const override { return entryPoint_; }
    uint64_t getImageBase() const override { return imageBase_; }

    std::vector<SectionInfo> getSections() const override { return sections_; }
    std::vector<SymbolInfo> getSymbols() const override { return symbols_; }
    std::vector<ImportInfo> getImports() const override { return imports_; }
    std::vector<ExportInfo> getExports() const override { return exports_; }
    std::vector<RelocationInfo> getRelocations() const override { return relocations_; }
    std::vector<DelayLoadInfo> getDelayLoads() const override { return {}; }

    bool isDyldCache() const override { return isDyldCache_; }
    std::vector<DyldCacheImageInfo> getDyldCacheImages() const override { return dyldCacheImages_; }

    std::vector<uint8_t> getBytes(uint64_t address, size_t size) const override {
        std::vector<uint8_t> result;
        result.reserve(size);

        uint64_t current = address;
        while (result.size() < size) {
            size_t remaining = size - result.size();

            if (const SectionInfo* section = findSectionContaining(current)) {
                uint64_t withinSection = current - section->virtualAddress;
                uint64_t span = getSectionSpan(*section);
                size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, span - withinSection));
                size_t copied = 0;

                if (withinSection < section->fileSize) {
                    uint64_t fileAvailable = section->fileSize - withinSection;
                    uint64_t fileOffset = section->fileOffset + withinSection;
                    size_t fileChunk = static_cast<size_t>(std::min<uint64_t>(chunk, fileAvailable));

                    if (fileOffset < rawData_.size() && fileChunk > 0) {
                        fileChunk = std::min(fileChunk, rawData_.size() - static_cast<size_t>(fileOffset));
                        result.insert(result.end(),
                                      rawData_.begin() + static_cast<size_t>(fileOffset),
                                      rawData_.begin() + static_cast<size_t>(fileOffset) + fileChunk);
                        copied = fileChunk;
                    }
                }

                if (copied < chunk) {
                    result.insert(result.end(), chunk - copied, 0);
                }

                current += chunk;
                continue;
            }

            uint64_t fileOffset = 0;
            if (!addressToFileOffset(current, fileOffset) || fileOffset >= rawData_.size()) {
                break;
            }

            size_t chunk = std::min(remaining, rawData_.size() - static_cast<size_t>(fileOffset));
            result.insert(result.end(),
                          rawData_.begin() + static_cast<size_t>(fileOffset),
                          rawData_.begin() + static_cast<size_t>(fileOffset) + chunk);
            current += chunk;
        }

        return result;
    }

    std::vector<uint8_t> getRawDataCopy() const override {
        return rawData_;
    }

    uint64_t virtualAddressToFileOffset(uint64_t vaddr) const override {
        for (const auto& section : sections_) {
            if (vaddr >= section.virtualAddress &&
                vaddr < section.virtualAddress + section.virtualSize) {
                uint64_t offset = vaddr - section.virtualAddress;
                if (offset < section.fileSize) {
                    return section.fileOffset + offset;
                }
                return UINT64_MAX;
            }
        }
        uint64_t fileOffset = 0;
        if (addressToFileOffset(vaddr, fileOffset)) {
            return fileOffset;
        }
        return UINT64_MAX;
    }

    bool populateProgram(ProgramDB* program) override {
        if (!program) return false;

        auto* mem = dynamic_cast<DefaultMemory*>(program->getMemory());
        if (!mem) return false;

        SymbolTable* symTable = program->getSymbolTable();
        FunctionManager* funcMgr = program->getFunctionManager();
        auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(program->getAddressFactory());
        if (!addrFactory) return false;

        if (!formatName_.empty())
            program->setExecutableFormat(formatName_);

        std::string languageId = guessLanguageFromArch(arch_, bitness_, isBigEndian());
        if (!languageId.empty() && languageId != "unknown") {
            program->setLanguageID(LanguageID(languageId));
        }
        program->setCompilerSpecID(CompilerSpecID(guessCompilerSpecFromArch(arch_, bitness_)));

        // GP-3960: Recognize Swift and golang ELF binaries from section names
        // (mirrors ElfLoader.detectCompilerName: SwiftUtils.isSwift, GoRttiMapper.hasGolangSections)
        if (formatName_ == "ELF") {
            auto hasSwiftSections = [&]() {
                for (const auto& section : sections_) {
                    if (section.name.rfind("__swift", 0) == 0 || section.name.rfind("swift", 0) == 0 ||
                        section.name.rfind(".sw5", 0) == 0) {
                        return true;
                    }
                }
                return false;
            };
            auto hasGolangSections = [&]() {
                for (const auto& section : sections_) {
                    if (section.name.find("gopclntab") != std::string::npos ||
                        section.name.find("go.buildinfo") != std::string::npos ||
                        section.name.find("go_buildinfo") != std::string::npos) {
                        return true;
                    }
                }
                return false;
            };
            std::string compilerName;
            if (hasSwiftSections()) {
                compilerName = "swift";
            } else if (hasGolangSections()) {
                compilerName = "golang";
            }
            if (!compilerName.empty()) {
                program->setCompiler(compilerName);
                program->setCompilerSpecID(CompilerSpecID(compilerName));
            }
        }

        AddressSpace* ramSpace = nullptr;
        for (const auto* space : addrFactory->getAddressSpaces()) {
            if (space->isMemorySpace()) {
                ramSpace = const_cast<AddressSpace*>(space);
                break;
            }
        }
        if (!ramSpace) return false;

        // Map ELF header + program/section header tables at file offsets (address 0)
        // so format analyzers can read and mark up the header structures.
        if (formatName_ == "ELF" && rawData_.size() >= 64) {
            bool is64 = (rawData_[4] == 2);
            auto rdU16 = [&](size_t off) -> uint16_t {
                return static_cast<uint16_t>(rawData_[off]) |
                       (static_cast<uint16_t>(rawData_[off + 1]) << 8);
            };
            auto rdU32 = [&](size_t off) -> uint32_t {
                uint32_t v = 0;
                for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(rawData_[off + i]) << (8 * i);
                return v;
            };
            auto rdU64 = [&](size_t off) -> uint64_t {
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(rawData_[off + i]) << (8 * i);
                return v;
            };
            uint64_t e_phoff = is64 ? rdU64(32) : rdU32(28);
            uint16_t e_phentsize = rdU16(is64 ? 54 : 42);
            uint16_t e_phnum = rdU16(is64 ? 56 : 44);
            uint64_t e_shoff = is64 ? rdU64(40) : rdU32(32);
            uint16_t e_shentsize = rdU16(is64 ? 58 : 46);
            uint16_t e_shnum = rdU16(is64 ? 60 : 48);
            uint64_t hdrEnd = 64;
            if (e_phoff > 0 && e_phnum > 0 && e_phentsize > 0) {
                hdrEnd = std::max(hdrEnd, e_phoff + static_cast<uint64_t>(e_phnum) * e_phentsize);
            }
            if (e_shoff > 0 && e_shnum > 0 && e_shentsize > 0) {
                hdrEnd = std::max(hdrEnd, e_shoff + static_cast<uint64_t>(e_shnum) * e_shentsize);
            }
            if (hdrEnd > rawData_.size()) hdrEnd = rawData_.size();
            if (hdrEnd > 64) {
                std::vector<uint8_t> hdrBytes(rawData_.begin(),
                                              rawData_.begin() + static_cast<std::ptrdiff_t>(hdrEnd));
                Address hdrAddr(ramSpace, 0);
                auto* hdrBlock = mem->createInitializedBlock(
                    "ELF_HEADER", hdrAddr, static_cast<long long>(hdrBytes.size()), false);
                if (hdrBlock) {
                    mem->setBytes(hdrAddr, hdrBytes.data(), static_cast<int>(hdrBytes.size()));
                    hdrBlock->setRead(true);
                    hdrBlock->setWrite(false);
                    hdrBlock->setExecute(false);
                }
            }
        }

        // Map PE header (image base to first section) so hex view shows full range
        if (imageBase_ > 0 && !sections_.empty()) {
            uint64_t firstSectionAddr = UINT64_MAX;
            for (const auto& section : sections_) {
                if (section.virtualAddress > imageBase_ && section.virtualAddress < firstSectionAddr)
                    firstSectionAddr = section.virtualAddress;
            }
            if (firstSectionAddr != UINT64_MAX) {
                uint64_t hdrSize = firstSectionAddr - imageBase_;
                if (hdrSize > 0 && hdrSize <= rawData_.size()) {
                    std::vector<uint8_t> hdrBytes = getBytes(imageBase_, hdrSize);
                    if (!hdrBytes.empty()) {
                        Address hdrAddr(ramSpace, static_cast<int64_t>(imageBase_));
                        auto* hdrBlock = mem->createInitializedBlock(
                            "IMAGE_HEADER", hdrAddr,
                            static_cast<long long>(hdrBytes.size()), false);
                        if (hdrBlock) {
                            mem->setBytes(hdrAddr, hdrBytes.data(),
                                          static_cast<int>(hdrBytes.size()));
                            hdrBlock->setRead(true);
                            hdrBlock->setWrite(false);
                            hdrBlock->setExecute(false);
                        }
                    }
                }
            }
        }

        int unnamedCounter = 0;
        for (const auto& section : sections_) {
            if (section.virtualSize == 0) continue;
            // Sanitize section name: empty names and control characters are rejected
            // by the memory block name validation.  Log and fix them here so the
            // caller gets a clear error message and the load proceeds.
            auto addrHex = [](uint64_t v) {
                std::ostringstream oss;
                oss << std::hex << v;
                return oss.str();
            };
            std::string blockName = section.name;
            if (blockName.empty()) {
                blockName = "unnamed_" + std::to_string(unnamedCounter++);
                Msg::warn("BinaryLoader",
                    "Section with empty name at VA 0x" +
                    addrHex(section.virtualAddress) +
                    "; using '" + blockName + "'");
            } else if (!Memory::isValidMemoryBlockName(blockName)) {
                std::string sanitized;
                for (char c : blockName) {
                    sanitized += (c < 0x20) ? '_' : c;
                }
                Msg::warn("BinaryLoader",
                    "Section name with invalid characters: '" + blockName +
                    "' at VA 0x" + addrHex(section.virtualAddress) +
                    "; sanitized to '" + sanitized + "'");
                blockName = sanitized;
            }

            Address startAddr(ramSpace, static_cast<int64_t>(section.virtualAddress));
            std::vector<uint8_t> bytes = getBytes(section.virtualAddress, section.virtualSize);
            if (bytes.empty() && section.fileSize > 0 && section.fileOffset + section.fileSize <= rawData_.size()) {
                bytes.assign(rawData_.begin() + static_cast<size_t>(section.fileOffset),
                             rawData_.begin() + static_cast<size_t>(section.fileOffset + section.fileSize));
            }

            DefaultMemoryBlock* block = nullptr;
            if (!bytes.empty()) {
                block = mem->createInitializedBlock(blockName, startAddr,
                    static_cast<long long>(bytes.size()), false);
                if (block) {
                    mem->setBytes(startAddr, bytes.data(), static_cast<int>(bytes.size()));
                }
            } else {
                block = mem->createUninitializedBlock(blockName, startAddr,
                    static_cast<long long>(section.virtualSize), false);
            }

            if (block) {
                block->setRead(section.isReadable);
                block->setWrite(section.isWritable);
                block->setExecute(section.isExecutable);
            }
        }

        for (const auto& sym : symbols_) {
            if (sym.isFunction && sym.address > 0) {
                Address entryAddr(ramSpace, static_cast<int64_t>(sym.address));
                uint64_t bodyEnd = sym.size > 0 ? sym.address + sym.size - 1 : sym.address;
                Address endAddr(ramSpace, static_cast<int64_t>(bodyEnd));
                AddressSet body(entryAddr, endAddr);
                funcMgr->createFunction(sym.name, entryAddr, body, SourceType::IMPORTED);
            }
        }

        // Defined non-function symbols become labels at their mapped address.
        for (const auto& sym : symbols_) {
            if (sym.isFunction || sym.address == 0) continue;
            Address symAddr(ramSpace, static_cast<int64_t>(sym.address));
            if (mem->getBlock(symAddr) && formatName_ == "COFF") {
                symTable->createLabel(symAddr, sym.name, SourceType::IMPORTED);
            }
        }

        for (const auto& imp : imports_) {
            if (imp.address > 0) {
                Address impAddr(ramSpace, static_cast<int64_t>(imp.address));
                symTable->createLabel(impAddr, imp.functionName, SourceType::IMPORTED);
            }
        }

        // GP-5900: normal exports become labels at their image address;
        // forwarded exports (RVA inside the export directory) become an
        // external target function plus a thunk function in EXTERNAL space.
        AddressSpace* externalSpace = nullptr;
        long nextExternalSymbolId = 0;
        uint64_t nextExternalOffset = 0;
        for (const auto& exp : exports_) {
            if (exp.address > 0) {
                Address expAddr(ramSpace, static_cast<int64_t>(exp.address));
                symTable->createLabel(expAddr, exp.name, SourceType::IMPORTED);
                continue;
            }
            if (!exp.isForwarder || exp.forwarderString.empty()) continue;

            std::string libName, symName;
            size_t dot = exp.forwarderString.find('.');
            if (dot != std::string::npos) {
                libName = exp.forwarderString.substr(0, dot);
                symName = exp.forwarderString.substr(dot + 1);
            } else {
                libName = exp.forwarderString;
                symName = exp.forwarderString;
            }
            if (libName.empty() || symName.empty()) continue;

            if (!externalSpace) {
                externalSpace =
                    const_cast<AddressSpace*>(addrFactory->getAddressSpace("EXTERNAL"));
                if (!externalSpace) {
                    externalSpace = new GenericAddressSpace("EXTERNAL", 64,
                                                            AddressSpace::TYPE_EXTERNAL, 0,
                                                            0, 0x7FFFFFFFLL);
                    addrFactory->addAddressSpace(externalSpace);
                }
            }

            ExternalManager* externals = program->getExternalManager();
            auto ensureLibrary = [&](const std::string& lib) -> Namespace* {
                Namespace* global = symTable->getGlobalNamespace();
                if (Namespace* ns = symTable->getNamespace(lib, global)) return ns;
                if (externals) externals->addExternalLibrary(lib, "");
                return symTable->createNameSpace(global, lib, SourceType::IMPORTED);
            };

            // Target: external function in the forwarded library.
            Function* target = nullptr;
            if (externals) {
                if (ExternalLocation* el = externals->getExternalLocation(libName, symName)) {
                    target = funcMgr->getFunctionAt(el->getAddress());
                }
            }
            if (!target) {
                Address targetAddr(externalSpace, static_cast<int64_t>(nextExternalOffset++));
                Namespace* libNs = ensureLibrary(libName);
                long targetSymId = nextExternalSymbolId++;
                symTable->createExternalSymbol(targetSymId, symName, targetAddr, libNs,
                                               SourceType::IMPORTED, true);
                if (externals) {
                    externals->addExternalLocation(libName, symName, targetAddr, targetSymId,
                                                   "", true);
                }
                AddressSet body(targetAddr, targetAddr);
                target = funcMgr->createFunction(symName, targetAddr, body, SourceType::IMPORTED);
                if (target) target->setExternal(true);
            }
            if (!target) continue;

            // Thunk: the forwarded export itself, in the exporting DLL's library.
            std::string thunkLib = exp.dllName.empty() ? "UNKNOWN" : exp.dllName;
            if (externals) {
                if (ExternalLocation* el = externals->getExternalLocation(thunkLib, exp.name)) {
                    if (funcMgr->getFunctionAt(el->getAddress())) continue;
                }
            }
            Address thunkAddr(externalSpace, static_cast<int64_t>(nextExternalOffset++));
            Namespace* thunkNs = ensureLibrary(thunkLib);
            long thunkSymId = nextExternalSymbolId++;
            symTable->createExternalSymbol(thunkSymId, exp.name, thunkAddr, thunkNs,
                                           SourceType::IMPORTED, true);
            if (externals) {
                externals->addExternalLocation(thunkLib, exp.name, thunkAddr, thunkSymId,
                                               exp.forwarderString, true);
            }
            AddressSet body(thunkAddr, thunkAddr);
            Function* thunk = funcMgr->createFunction(exp.name, thunkAddr, body,
                                                      SourceType::IMPORTED);
            if (thunk) {
                thunk->setExternal(true);
                thunk->setThunk(true);
                thunk->setThunkedFunction(target);
            }
        }

        if (entryPoint_ > 0) {
            Address entryAddr(ramSpace, static_cast<int64_t>(entryPoint_));
            Address baseAddr(ramSpace, static_cast<int64_t>(imageBase_));
            program->setImageBase(baseAddr);

            if (funcMgr && !funcMgr->getFunctionAt(entryAddr)) {
                uint64_t bodyEnd = entryPoint_;
                if (const SectionInfo* entrySection = findSectionContaining(entryPoint_)) {
                    uint64_t span = getSectionSpan(*entrySection);
                    if (span > 0) {
                        uint64_t sectionEnd = entrySection->virtualAddress + span - 1;
                        bodyEnd = std::min(sectionEnd, entryPoint_ + 63);
                    }
                }
                if (bodyEnd < entryPoint_) {
                    bodyEnd = entryPoint_;
                }
                AddressSet body(entryAddr, Address(ramSpace, static_cast<int64_t>(bodyEnd)));
                try {
                    funcMgr->createFunction("entry", entryAddr, body, SourceType::ANALYSIS);
                } catch (const std::exception&) {
                    // Existing analyzed/imported functions may overlap the entry range.
                }
            }
        }

        return true;
    }

private:
    static constexpr uint64_t INVALID_FILE_OFFSET = std::numeric_limits<uint64_t>::max();

    void reset() {
        formatName_.clear();
        arch_.clear();
        bitness_ = 32;
        entryPoint_ = 0;
        imageBase_ = 0;
        fileSize_ = 0;
        rawData_.clear();
        sections_.clear();
        symbols_.clear();
        imports_.clear();
        exports_.clear();
        relocations_.clear();
        cpusubtype_ = 0;
        dysymtabIndirectSymOffset_ = 0;
        dysymtabIndirectSymCount_ = 0;
        machONlistNames_.clear();
        machoDylibNames_.clear();
        machoSegments_.clear();
        machoTextAddr_ = 0;
        chainedFixupsOff_ = 0;
        chainedFixupsSize_ = 0;
        dyldCacheImages_.clear();
        isDyldCache_ = false;
    }

    static uint64_t getSectionSpan(const SectionInfo& section) {
        return std::max(section.virtualSize, section.fileSize);
    }

    const SectionInfo* findSectionContaining(uint64_t address) const {
        for (const auto& section : sections_) {
            uint64_t span = getSectionSpan(section);
            if (span == 0 || address < section.virtualAddress) {
                continue;
            }
            if (address - section.virtualAddress < span) {
                return &section;
            }
        }
        return nullptr;
    }

    bool addressToFileOffset(uint64_t address, uint64_t& fileOffset) const {
        if (const SectionInfo* section = findSectionContaining(address)) {
            uint64_t withinSection = address - section->virtualAddress;
            if (withinSection >= section->fileSize) {
                return false;
            }
            fileOffset = section->fileOffset + withinSection;
            return fileOffset < rawData_.size();
        }

        if (formatName_ == "PE" && imageBase_ != 0 && address >= imageBase_) {
            uint64_t headerOffset = address - imageBase_;
            if (headerOffset < rawData_.size()) {
                fileOffset = headerOffset;
                return true;
            }
        }

        if (address < rawData_.size()) {
            fileOffset = address;
            return true;
        }

        return false;
    }

    bool isValidFileOffset(uint64_t offset) const {
        return offset != INVALID_FILE_OFFSET && offset < rawData_.size();
    }

    bool parsePE() {
        formatName_ = "PE";

        uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(rawData_.data() + 0x3C);
        if (e_lfanew + 24 > rawData_.size()) return false;

        uint32_t peSig = *reinterpret_cast<uint32_t*>(rawData_.data() + e_lfanew);
        if (peSig != 0x00004550) return false;

        uint16_t machine = *reinterpret_cast<uint16_t*>(rawData_.data() + e_lfanew + 4);
        uint16_t numSections = *reinterpret_cast<uint16_t*>(rawData_.data() + e_lfanew + 6);
        uint16_t optHeaderSize = *reinterpret_cast<uint16_t*>(rawData_.data() + e_lfanew + 20);

        switch (machine) {
            case 0x14c: arch_ = "x86"; bitness_ = 32; break;
            case 0x8664: arch_ = "x86"; bitness_ = 64; break;
            case 0x1c0: arch_ = "ARM"; bitness_ = 32; break;
            case 0xAA64: arch_ = "AARCH64"; bitness_ = 64; break;
            default: arch_ = "unknown"; bitness_ = 32; break;
        }

        uint32_t optHeaderOffset = e_lfanew + 24;
        if (optHeaderOffset + optHeaderSize > rawData_.size()) return false;

        uint16_t magic = *reinterpret_cast<uint16_t*>(rawData_.data() + optHeaderOffset);
        if (magic == 0x10b) {
            imageBase_ = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 28);
            entryPoint_ = imageBase_ + *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 16);
        } else if (magic == 0x20b) {
            imageBase_ = *reinterpret_cast<uint64_t*>(rawData_.data() + optHeaderOffset + 24);
            entryPoint_ = imageBase_ + *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 16);
        }

        uint32_t sectionOffset = optHeaderOffset + optHeaderSize;
        for (uint16_t i = 0; i < numSections; ++i) {
            if (sectionOffset + 40 > rawData_.size()) break;

            SectionInfo section{};
            char nameBuf[9] = {0};
            std::memcpy(nameBuf, rawData_.data() + sectionOffset, 8);
            section.name = nameBuf;

            section.virtualSize = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 8);
            section.virtualAddress = imageBase_ + *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 12);
            section.fileSize = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 16);
            section.fileOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 20);

            uint32_t chars = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 36);
            section.isReadable = (chars & 0x40000000) != 0;
            section.isWritable = (chars & 0x80000000) != 0;
            section.isExecutable = (chars & 0x20000000) != 0;

            sections_.push_back(section);
            sectionOffset += 40;
        }

        parseImports();
        parseExports();
        parseRelocations();

        return true;
    }

    uint16_t elf16(size_t off) const {
        if (off + 2 > rawData_.size()) return 0;
        uint16_t v = *reinterpret_cast<const uint16_t*>(rawData_.data() + off);
        if (elfBigEndian_) return static_cast<uint16_t>((v >> 8) | (v << 8));
        return v;
    }

    uint32_t elf32(size_t off) const {
        if (off + 4 > rawData_.size()) return 0;
        uint32_t v = *reinterpret_cast<const uint32_t*>(rawData_.data() + off);
        if (elfBigEndian_)
            return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24);
        return v;
    }

    int32_t elfs32(size_t off) const { return static_cast<int32_t>(elf32(off)); }

    uint64_t elf64(size_t off) const {
        if (off + 8 > rawData_.size()) return 0;
        uint64_t v = *reinterpret_cast<const uint64_t*>(rawData_.data() + off);
        if (elfBigEndian_)
            return ((v & 0xFFULL) << 56) | ((v & 0xFF00ULL) << 40) | ((v & 0xFF0000ULL) << 24) |
                   ((v & 0xFF000000ULL) << 8) | ((v >> 8) & 0xFF000000ULL) |
                   ((v >> 24) & 0xFF0000ULL) | ((v >> 40) & 0xFF00ULL) | (v >> 56);
        return v;
    }

    int64_t elfs64(size_t off) const { return static_cast<int64_t>(elf64(off)); }

    // COFF is always little-endian.
    uint16_t coff16(size_t off) const {
        if (off + 2 > rawData_.size()) return 0;
        return static_cast<uint16_t>(rawData_[off]) |
               (static_cast<uint16_t>(rawData_[off + 1]) << 8);
    }

    uint32_t coff32(size_t off) const {
        if (off + 4 > rawData_.size()) return 0;
        return static_cast<uint32_t>(rawData_[off]) |
               (static_cast<uint32_t>(rawData_[off + 1]) << 8) |
               (static_cast<uint32_t>(rawData_[off + 2]) << 16) |
               (static_cast<uint32_t>(rawData_[off + 3]) << 24);
    }

    uint64_t coff64(size_t off) const {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(rawData_[off + i]) << (8 * i);
        return v;
    }

    bool isCoffMachine(uint16_t machine) const {
        switch (machine) {
            case 0x8664:  // AMD64
            case 0xAA64:  // ARM64
            case 0x14C:   // I386
            case 0x1C0:   // ARM
            case 0x1C4:   // ARMNT
            case 0x1C2:   // THUMB
                return true;
            default:
                return false;
        }
    }

    bool parseELF() {
        formatName_ = "ELF";
        bitness_ = (rawData_[4] == 2) ? 64 : 32;
        elfBigEndian_ = (rawData_.size() >= 6 && rawData_[5] == 2);

        uint16_t machine = elf16(18);
        switch (machine) {
            case 0x03: arch_ = "x86"; break;
            case 0x3E: arch_ = "x86"; break;
            case 0x28: arch_ = "ARM"; break;
            case 0xB7: arch_ = "AARCH64"; break;
            case 0x08: arch_ = "MIPS"; break;
            case 0x14: arch_ = "PowerPC"; break;
            case 0x15: arch_ = "PowerPC"; break;
            case 0xF3: arch_ = "RISCV"; break;
            default: arch_ = "unknown"; break;
        }

        if (bitness_ == 32) {
            entryPoint_ = elf32(24);
        } else {
            entryPoint_ = elf64(24);
        }

        imageBase_ = 0;

        if (bitness_ == 32) {
            parseELF32();
        } else {
            parseELF64();
        }

        parseELFSymbols();
        parseELFImports();
        parseELFRelocations();

        // GP-7056: with section headers stripped (e_shoff == 0) the passes
        // above find nothing; recover segments + dynamic imports from the
        // PT_DYNAMIC program header instead.
        if (sections_.empty()) parseELFStripped();

        return true;
    }

    void parseImports() {
        if (bitness_ == 32) {
            parsePE32Imports();
        } else {
            parsePE64Imports();
        }
    }

    void parsePE32Imports() {
        uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(rawData_.data() + 0x3C);
        uint32_t optHeaderOffset = e_lfanew + 24;
        if (optHeaderOffset + 128 > rawData_.size()) return;

        uint32_t importRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 104);
        if (importRVA == 0) return;

        uint64_t importOffset = rvaToFileOffset(importRVA);
        if (!isValidFileOffset(importOffset)) return;

        uint64_t descOffset = importOffset;
        while (descOffset + 20 <= rawData_.size()) {
            uint32_t nameRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + descOffset + 12);
            uint32_t iltRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + descOffset);
            uint32_t iatRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + descOffset + 16);

            if (nameRVA == 0 && iltRVA == 0 && iatRVA == 0) break;

            std::string libName = readStringAtRVA(nameRVA);
            if (libName.empty()) break;

            uint64_t thunkOffset = rvaToFileOffset(iltRVA != 0 ? iltRVA : iatRVA);
            if (!isValidFileOffset(thunkOffset)) { descOffset += 20; continue; }

            uint64_t iltFileOffset = rvaToFileOffset(iltRVA != 0 ? iltRVA : iatRVA);
            while (thunkOffset + 4 <= rawData_.size()) {
                uint32_t thunk = *reinterpret_cast<uint32_t*>(rawData_.data() + thunkOffset);
                if (thunk == 0) break;

                if (!(thunk & 0x80000000)) {
                    uint32_t hintNameRVA = thunk;
                    uint64_t hintNameOffset = rvaToFileOffset(hintNameRVA);
                    if (isValidFileOffset(hintNameOffset) && hintNameOffset + 2 < rawData_.size()) {
                        std::string funcName = readStringAtRVA(hintNameRVA + 2);
                        if (!funcName.empty()) {
                            ImportInfo imp{};
                            imp.libraryName = libName;
                            imp.functionName = funcName;
                            imp.address = imageBase_ + iatRVA + (thunkOffset - iltFileOffset);
                            imports_.push_back(imp);
                        }
                    }
                }
                thunkOffset += 4;
            }
            descOffset += 20;
        }
    }

    void parsePE64Imports() {
        uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(rawData_.data() + 0x3C);
        uint32_t optHeaderOffset = e_lfanew + 24;
        if (optHeaderOffset + 144 > rawData_.size()) return;

        uint32_t importRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 120);
        if (importRVA == 0) return;

        uint64_t importOffset = rvaToFileOffset(importRVA);
        if (!isValidFileOffset(importOffset)) return;

        uint64_t descOffset = importOffset;
        while (descOffset + 20 <= rawData_.size()) {
            uint32_t nameRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + descOffset + 12);
            uint32_t iltRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + descOffset);
            uint32_t iatRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + descOffset + 16);

            if (nameRVA == 0 && iltRVA == 0 && iatRVA == 0) break;

            std::string libName = readStringAtRVA(nameRVA);
            if (libName.empty()) break;

            uint64_t thunkOffset = rvaToFileOffset(iltRVA != 0 ? iltRVA : iatRVA);
            if (!isValidFileOffset(thunkOffset)) { descOffset += 20; continue; }

            uint64_t iltFileOffset = rvaToFileOffset(iltRVA != 0 ? iltRVA : iatRVA);
            while (thunkOffset + 8 <= rawData_.size()) {
                uint64_t thunk = *reinterpret_cast<uint64_t*>(rawData_.data() + thunkOffset);
                if (thunk == 0) break;

                if (!(thunk & 0x8000000000000000ULL)) {
                    uint32_t hintNameRVA = static_cast<uint32_t>(thunk);
                    uint64_t hintNameOffset = rvaToFileOffset(hintNameRVA);
                    if (isValidFileOffset(hintNameOffset) && hintNameOffset + 2 < rawData_.size()) {
                        std::string funcName = readStringAtRVA(hintNameRVA + 2);
                        if (!funcName.empty()) {
                            ImportInfo imp{};
                            imp.libraryName = libName;
                            imp.functionName = funcName;
                            imp.address = imageBase_ + iatRVA + (thunkOffset - iltFileOffset);
                            imports_.push_back(imp);
                        }
                    }
                }
                thunkOffset += 8;
            }
            descOffset += 20;
        }
    }

    void parseExports() {
        uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(rawData_.data() + 0x3C);
        uint32_t optHeaderOffset = e_lfanew + 24;

        uint32_t exportDirRVA = 0;
        uint32_t exportDirSize = 0;
        if (bitness_ == 32) {
            if (optHeaderOffset + 104 > rawData_.size()) return;
            exportDirRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 96);
            exportDirSize = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 100);
        } else {
            if (optHeaderOffset + 120 > rawData_.size()) return;
            exportDirRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 112);
            exportDirSize = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 116);
        }

        if (exportDirRVA == 0) return;
        if (exportDirSize == 0) exportDirSize = 40; // fall back to the struct itself

        uint64_t exportOffset = rvaToFileOffset(exportDirRVA);
        if (!isValidFileOffset(exportOffset) || exportOffset + 40 > rawData_.size()) return;

        uint32_t dllNameRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + exportOffset + 12);
        uint32_t numNames = *reinterpret_cast<uint32_t*>(rawData_.data() + exportOffset + 24);
        uint32_t namesRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + exportOffset + 32);
        uint32_t ordinalsRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + exportOffset + 36);
        uint32_t functionsRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + exportOffset + 28);

        uint64_t namesOffset = rvaToFileOffset(namesRVA);
        uint64_t ordinalsOffset = rvaToFileOffset(ordinalsRVA);
        uint64_t functionsOffset = rvaToFileOffset(functionsRVA);
        if (!isValidFileOffset(namesOffset) || !isValidFileOffset(ordinalsOffset) ||
            !isValidFileOffset(functionsOffset)) {
            return;
        }

        for (uint32_t i = 0; i < numNames; i++) {
            if (namesOffset + i * 4 + 4 > rawData_.size()) break;
            if (ordinalsOffset + i * 2 + 2 > rawData_.size()) break;
            if (functionsOffset + i * 4 + 4 > rawData_.size()) break;

            uint32_t nameRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + namesOffset + i * 4);
            uint16_t ordinal = *reinterpret_cast<uint16_t*>(rawData_.data() + ordinalsOffset + i * 2);
            uint32_t funcRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + functionsOffset + ordinal * 4);

            std::string name = readStringAtRVA(nameRVA);
            if (name.empty()) continue;

            ExportInfo exp{};
            exp.name = name;
            exp.dllName = readStringAtRVA(dllNameRVA);
            // GP-5900: a function RVA that falls inside the export directory is
            // a forwarder: the bytes there are "DLL.SymbolName", not code.
            if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize) {
                exp.isForwarder = true;
                exp.forwarderString = readStringAtRVA(funcRVA);
                exp.address = 0;
                exports_.push_back(exp);
                continue;
            }
            exp.address = imageBase_ + funcRVA;
            exports_.push_back(exp);

            SymbolInfo sym{};
            sym.name = name;
            sym.address = exp.address;
            sym.size = 0;
            sym.isFunction = true;
            sym.isExternal = false;
            symbols_.push_back(sym);
        }
    }

    void parseRelocations() {
        uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(rawData_.data() + 0x3C);
        uint32_t optHeaderOffset = e_lfanew + 24;

        uint32_t baseRelocRVA = 0, baseRelocSize = 0;
        if (bitness_ == 32) {
            if (optHeaderOffset + 168 > rawData_.size()) return;
            baseRelocRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 152);
            baseRelocSize = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 156);
        } else {
            if (optHeaderOffset + 168 > rawData_.size()) return;
            baseRelocRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 160);
            baseRelocSize = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 164);
        }

        if (baseRelocRVA == 0 || baseRelocSize == 0) return;

        uint64_t relocOffset = rvaToFileOffset(baseRelocRVA);
        if (!isValidFileOffset(relocOffset)) return;
        uint64_t relocEnd = std::min<uint64_t>(relocOffset + baseRelocSize, rawData_.size());

        while (relocOffset + 8 <= relocEnd && relocOffset + 8 <= rawData_.size()) {
            uint32_t pageRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + relocOffset);
            uint32_t blockSize = *reinterpret_cast<uint32_t*>(rawData_.data() + relocOffset + 4);

            if (pageRVA == 0 && blockSize == 0) break;
            if (blockSize < 8) break;

            uint32_t numEntries = (blockSize - 8) / 2;
            uint32_t entriesOffset = relocOffset + 8;

            for (uint32_t i = 0; i < numEntries; i++) {
                if (entriesOffset + i * 2 + 2 > rawData_.size()) break;
                uint16_t entry = *reinterpret_cast<uint16_t*>(rawData_.data() + entriesOffset + i * 2);
                uint16_t type = (entry >> 12) & 0xF;
                uint16_t offset = entry & 0xFFF;

                if (type == 0) continue;

                RelocationInfo reloc{};
                reloc.address = imageBase_ + pageRVA + offset;
                reloc.type = type;
                relocations_.push_back(reloc);
            }

            relocOffset += blockSize;
        }
    }

    void parseELF32() {
        uint32_t shoff = elf32(32);
        uint16_t shnum = elf16(48);
        uint16_t shentsize = elf16(46);
        uint16_t shstrndx = elf16(50);

        std::vector<uint32_t> sectionNames(shnum);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;

            SectionInfo section{};
            uint32_t nameIdx = elf32(secOffset);
            section.type = elf32(secOffset + 4);
            section.virtualAddress = elf32(secOffset + 12);
            section.fileOffset = elf32(secOffset + 16);
            section.fileSize = elf32(secOffset + 20);
            section.virtualSize = section.fileSize;

            uint32_t flags = elf32(secOffset + 8);
            section.isReadable = (flags & 0x2) != 0;
            section.isWritable = (flags & 0x1) != 0;
            section.isExecutable = (flags & 0x4) != 0;

            sectionNames[i] = nameIdx;
            sections_.push_back(section);
        }

        if (shstrndx < shnum) {
            uint32_t strSecOffset = shoff + shstrndx * shentsize;
            uint32_t strOffset = elf32(strSecOffset + 16);

            for (size_t i = 0; i < sections_.size(); i++) {
                uint32_t nameOff = strOffset + sectionNames[i];
                if (nameOff < rawData_.size()) {
                    sections_[i].name = reinterpret_cast<const char*>(rawData_.data() + nameOff);
                }
            }
        }
    }

    void parseELF64() {
        uint64_t shoff = elf64(40);
        uint16_t shnum = elf16(60);
        uint16_t shentsize = elf16(58);
        uint16_t shstrndx = elf16(62);

        std::vector<uint32_t> sectionNames(shnum);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;

            SectionInfo section{};
            uint32_t nameIdx = elf32(secOffset);
            section.type = elf32(secOffset + 4);
            section.virtualAddress = elf64(secOffset + 16);
            section.fileOffset = elf64(secOffset + 24);
            section.fileSize = elf64(secOffset + 32);
            section.virtualSize = section.fileSize;

            uint64_t flags = elf64(secOffset + 8);
            section.isReadable = (flags & 0x2) != 0;
            section.isWritable = (flags & 0x1) != 0;
            section.isExecutable = (flags & 0x4) != 0;

            sectionNames[i] = nameIdx;
            sections_.push_back(section);
        }

        if (shstrndx < shnum) {
            uint64_t strSecOffset = shoff + shstrndx * shentsize;
            uint64_t strOffset = elf64(strSecOffset + 24);

            for (size_t i = 0; i < sections_.size(); i++) {
                uint64_t nameOff = strOffset + sectionNames[i];
                if (nameOff < rawData_.size()) {
                    sections_[i].name = reinterpret_cast<const char*>(rawData_.data() + nameOff);
                }
            }
        }
    }

    void parseELFSymbols() {
        if (bitness_ == 32) {
            parseELF32Symbols();
        } else {
            parseELF64Symbols();
        }
    }

    void parseELF32Symbols() {
        uint32_t shoff = elf32(32);
        uint16_t shnum = elf16(48);
        uint16_t shentsize = elf16(46);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;

            uint32_t type = elf32(secOffset + 4);
            if (type != 2 && type != 11) continue;

            uint32_t symOffset = elf32(secOffset + 16);
            uint32_t symSize = elf32(secOffset + 20);
            uint32_t linkIdx = elf32(secOffset + 24);
            uint32_t entSize = elf32(secOffset + 36);
            if (entSize == 0) entSize = 16;

            uint32_t strTabOffset = 0;
            if (linkIdx < shnum) {
                uint32_t linkOffset = shoff + linkIdx * shentsize;
                strTabOffset = elf32(linkOffset + 16);
            }

            uint32_t numSymbols = symSize / entSize;
            for (uint32_t j = 0; j < numSymbols; j++) {
                uint32_t symOff = symOffset + j * entSize;
                if (symOff + 16 > rawData_.size()) break;

                uint32_t nameIdx = elf32(symOff);
                uint32_t value = elf32(symOff + 4);
                uint32_t size = elf32(symOff + 8);
                uint8_t info = rawData_[symOff + 12];
                uint8_t bind = info >> 4;
                uint8_t stype = info & 0xF;
                uint16_t shndx = elf16(symOff + 14);

                if (nameIdx == 0 || value == 0) continue;

                std::string name;
                if (strTabOffset + nameIdx < rawData_.size()) {
                    name = reinterpret_cast<const char*>(rawData_.data() + strTabOffset + nameIdx);
                }
                if (name.empty()) continue;

                SymbolInfo sym{};
                sym.name = name;
                sym.address = value;
                sym.size = size;
                sym.isFunction = (stype == 2);
                // GP-7057: external iff GLOBAL or WEAK binding and SHN_UNDEF section index
                // (ElfSymbol.isExternal disregards symbol type, value and size)
                sym.isExternal = (bind == 1 || bind == 2) && shndx == 0;
                symbols_.push_back(sym);
            }
        }
    }

    void parseELF64Symbols() {
        uint64_t shoff = elf64(40);
        uint16_t shnum = elf16(60);
        uint16_t shentsize = elf16(58);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;

            uint32_t type = elf32(secOffset + 4);
            if (type != 2 && type != 11) continue;

            uint64_t symOffset = elf64(secOffset + 24);
            uint64_t symSize = elf64(secOffset + 32);
            uint32_t linkIdx = elf32(secOffset + 40);
            uint64_t entSize = elf64(secOffset + 56);
            if (entSize == 0) entSize = 24;

            uint64_t strTabOffset = 0;
            if (linkIdx < shnum) {
                uint64_t linkOffset = shoff + linkIdx * shentsize;
                strTabOffset = elf64(linkOffset + 24);
            }

            uint64_t numSymbols = symSize / entSize;
            for (uint64_t j = 0; j < numSymbols; j++) {
                uint64_t symOff = symOffset + j * entSize;
                if (symOff + 24 > rawData_.size()) break;

                uint32_t nameIdx = elf32(symOff);
                uint8_t info = rawData_[symOff + 4];
                uint8_t bind = info >> 4;
                uint8_t stype = info & 0xF;
                uint16_t shndx = elf16(symOff + 6);
                uint64_t value = elf64(symOff + 8);
                uint64_t size = elf64(symOff + 16);

                if (nameIdx == 0 || value == 0) continue;

                std::string name;
                if (strTabOffset + nameIdx < rawData_.size()) {
                    name = reinterpret_cast<const char*>(rawData_.data() + strTabOffset + nameIdx);
                }
                if (name.empty()) continue;

                SymbolInfo sym{};
                sym.name = name;
                sym.address = value;
                sym.size = size;
                sym.isFunction = (stype == 2);
                // GP-7057: external iff GLOBAL or WEAK binding and SHN_UNDEF section index
                // (ElfSymbol.isExternal disregards symbol type, value and size)
                sym.isExternal = (bind == 1 || bind == 2) && shndx == 0;
                symbols_.push_back(sym);
            }
        }
    }

    void parseELFImports() {
        if (bitness_ == 32) {
            parseELF32Dynamic();
        } else {
            parseELF64Dynamic();
        }
    }

    void parseELF32Dynamic() {
        uint32_t shoff = elf32(32);
        uint16_t shnum = elf16(48);
        uint16_t shentsize = elf16(46);

        uint32_t dynOffset = 0, dynSize = 0, strTabOffset = 0;
        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;
            uint32_t type = elf32(secOffset + 4);
            if (type == 6) {
                dynOffset = elf32(secOffset + 16);
                dynSize = elf32(secOffset + 20);
            }
            if (type == 3) {
                strTabOffset = elf32(secOffset + 16);
            }
        }

        if (dynOffset == 0) return;

        uint32_t numEntries = dynSize / 8;
        for (uint32_t i = 0; i < numEntries; i++) {
            uint32_t entryOffset = dynOffset + i * 8;
            if (entryOffset + 8 > rawData_.size()) break;

            int32_t tag = elfs32(entryOffset);
            uint32_t val = elf32(entryOffset + 4);

            if (tag == 1) {
                std::string libName;
                if (strTabOffset + val < rawData_.size()) {
                    libName = reinterpret_cast<const char*>(rawData_.data() + strTabOffset + val);
                }
                if (!libName.empty()) {
                    ImportInfo imp{};
                    imp.libraryName = libName;
                    imp.functionName = "(dynamic)";
                    imp.address = 0;
                    imports_.push_back(imp);
                }
            }
            if (tag == 0) break;
        }
    }

    void parseELF64Dynamic() {
        uint64_t shoff = elf64(40);
        uint16_t shnum = elf16(60);
        uint16_t shentsize = elf16(58);

        uint64_t dynOffset = 0, dynSize = 0, strTabOffset = 0;
        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;
            uint32_t type = elf32(secOffset + 4);
            if (type == 6) {
                dynOffset = elf64(secOffset + 24);
                dynSize = elf64(secOffset + 32);
            }
            if (type == 3) {
                strTabOffset = elf64(secOffset + 24);
            }
        }

        if (dynOffset == 0) return;

        uint64_t numEntries = dynSize / 16;
        for (uint64_t i = 0; i < numEntries; i++) {
            uint64_t entryOffset = dynOffset + i * 16;
            if (entryOffset + 16 > rawData_.size()) break;

            int64_t tag = elfs64(entryOffset);
            uint64_t val = elf64(entryOffset + 8);

            if (tag == 1) {
                std::string libName;
                if (strTabOffset + val < rawData_.size()) {
                    libName = reinterpret_cast<const char*>(rawData_.data() + strTabOffset + val);
                }
                if (!libName.empty()) {
                    ImportInfo imp{};
                    imp.libraryName = libName;
                    imp.functionName = "(dynamic)";
                    imp.address = 0;
                    imports_.push_back(imp);
                }
            }
            if (tag == 0) break;
        }
    }

    // ELF dynamic relocations: resolve PLT/GOT import slots to symbol names.
    // The dynamic symbol table lists imports as UND symbols with value 0, so
    // parseELFSymbols() skips them; the relocation sections (.rela.plt /
    // .rela.dyn) map each GOT slot (and its PLT stub) to the imported symbol.
    // This gives dynamically-linked ELFs named imports instead of bare
    // "(dynamic)" library records or unresolved GOT-relative indirect calls.
    void parseELFRelocations() {
        if (bitness_ == 32) {
            parseELF32Relocations();
        } else {
            parseELF64Relocations();
        }
    }

    // PLT layout per arch: {header bytes, stub size}. Standard values used by
    // the system linkers: AArch64 = 32-byte header + 16-byte stubs,
    // x86/x86-64 = 16-byte header + 16-byte stubs. ARM is detected from the
    // .plt bytes (see armPltStubLayout) because lld and binutils emit
    // different layouts. MIPS and PPC have no contiguous .plt stub region:
    // MIPS uses .MIPS.stubs and PPC's .plt is a GOT-style 4-byte slot table
    // whose values are stub addresses in .text (already named by the linker's
    // .plt_pic32.* symbols), so {0, 0} skips the phantom stub import.
    static std::pair<uint64_t, uint64_t> pltLayout(const std::string& arch) {
        if (arch == "AARCH64") return {32, 16};
        if (arch == "MIPS" || arch == "PowerPC") return {0, 0};
        return {16, 16}; // x86, RISCV, default
    }

    // ARM PLT layouts differ per linker: lld emits a 32-byte header (16 bytes
    // of PLT0 code + 16 bytes of padding) with 16-byte stub slots, binutils a
    // 20-byte header with 12-byte stubs. Detect the real stub base and stride
    // from the .plt bytes instead of assuming: every ARM stub starts with
    // `add ip, pc, #imm` (0xe28fc600).
    std::pair<uint64_t, uint64_t> armPltStubLayout() {
        for (const auto& s : sections_) {
            if (s.name != ".plt" || s.fileSize < 16 ||
                s.fileOffset >= rawData_.size()) continue;
            std::vector<uint64_t> starts;
            const uint8_t* p = rawData_.data() + s.fileOffset;
            uint64_t n = std::min<uint64_t>(s.fileSize, rawData_.size() - s.fileOffset);
            for (uint64_t i = 4; i + 4 <= n; ++i) {
                bool match = elfBigEndian_
                    ? (p[i] == 0xe2 && p[i+1] == 0x8f && p[i+2] == 0xc6 && p[i+3] == 0x00)
                    : (p[i] == 0x00 && p[i+1] == 0xc6 && p[i+2] == 0x8f && p[i+3] == 0xe2);
                if (match) {
                    starts.push_back(s.virtualAddress + i);
                    if (starts.size() == 2) break;
                }
            }
            if (starts.size() >= 1)
                return {starts[0], starts.size() >= 2 ? starts[1] - starts[0] : 16};
        }
        return {0, 0};
    }

    static uint32_t jumpSlotRelocType(const std::string& arch) {
        // R_*_JUMP_SLOT: x86/x86-64 = 7, ARM32 = 22, AARCH64 = 0x402,
        // MIPS = 2, PPC = 21, RISCV = 5.
        if (arch == "ARM") return 22;
        if (arch == "AARCH64") return 0x402;
        if (arch == "MIPS") return 2;
        if (arch == "PowerPC") return 21;
        if (arch == "RISCV") return 5;
        return 7;
    }

    void parseELF64Relocations() {
        uint64_t shoff = elf64(40);
        uint16_t shnum = elf16(60);
        uint16_t shentsize = elf16(58);

        uint64_t pltVaddr = 0;
        for (const auto& s : sections_)
            if (s.name == ".plt") { pltVaddr = s.virtualAddress; break; }

        uint64_t pltStubBase = 0, pltStubSize = 0;
        if (arch_ == "ARM") {
            std::tie(pltStubBase, pltStubSize) = armPltStubLayout();
        } else {
            uint64_t pltHeader;
            std::tie(pltHeader, pltStubSize) = pltLayout(arch_);
            pltStubBase = pltVaddr + pltHeader;
        }
        uint32_t jsType = jumpSlotRelocType(arch_);
        uint64_t stubIdx = 0;

        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;
            uint32_t type = elf32(secOffset + 4);
            // SHT_RELA = 4, SHT_REL = 9
            if (type != 4 && type != 9) continue;

            uint64_t relOffset = elf64(secOffset + 24);
            uint64_t relSize = elf64(secOffset + 32);
            uint64_t entSize = elf64(secOffset + 56);
            if (entSize == 0) entSize = (type == 4) ? 24 : 16;
            uint32_t linkIdx = elf32(secOffset + 40); // symbol table section index

            // Symbol table's linked string table
            uint64_t strTabOffset = 0;
            if (linkIdx < shnum) {
                uint64_t lso = shoff + linkIdx * shentsize;
                uint32_t strIdx = elf32(lso + 40);
                if (strIdx < shnum) {
                    uint64_t strso = shoff + strIdx * shentsize;
                    strTabOffset = elf64(strso + 24);
                }
            }

            uint64_t numRels = relSize / entSize;
            for (uint64_t j = 0; j < numRels; ++j) {
                uint64_t rOffset = relOffset + j * entSize;
                if (rOffset + 16 > rawData_.size()) break;
                uint64_t rInfo = elf64(rOffset + 8);
                uint64_t symIdx = rInfo >> 32;
                uint32_t rType = static_cast<uint32_t>(rInfo & 0xFFFFFFFF);

                std::string symName;
                if (strTabOffset != 0 && linkIdx < shnum) {
                    uint64_t lso = shoff + linkIdx * shentsize;
                    uint64_t symTabOff = elf64(lso + 24);
                    uint64_t symEnt = elf64(lso + 56);
                    if (symEnt == 0) symEnt = 24;
                    uint64_t symOff = symTabOff + symIdx * symEnt;
                    if (symOff + 8 <= rawData_.size()) {
                        uint32_t nameIdx = elf32(symOff);
                        if (nameIdx != 0 && strTabOffset + nameIdx < rawData_.size()) {
                            symName = reinterpret_cast<const char*>(rawData_.data() + strTabOffset + nameIdx);
                        }
                    }
                }
                if (symName.empty() || symName == "(dynamic)") continue;

                uint64_t gotSlot = elf64(rOffset); // r_offset = GOT slot VA

                if (rType == jsType) {
                    // JUMP_SLOT: function import. Name both the GOT slot
                    // (the indirect target) and its PLT stub.
                    ImportInfo imp{};
                    imp.functionName = symName;
                    imp.address = gotSlot;
                    imports_.push_back(imp);

                    if (pltStubBase != 0 && pltStubSize > 0) {
                        ImportInfo stub{};
                        stub.functionName = symName;
                        stub.address = pltStubBase + stubIdx * pltStubSize;
                        imports_.push_back(stub);
                    }
                    stubIdx++;
                } else if (rType == 6 || rType == 0x401 || rType == 21 ||
                           rType == 1 || rType == 20) {
                    // GLOB_DAT / data import: name the GOT slot only.
                    ImportInfo imp{};
                    imp.functionName = symName;
                    imp.address = gotSlot;
                    imports_.push_back(imp);
                }
            }
        }
    }

    void parseELF32Relocations() {
        uint32_t shoff = elf32(32);
        uint16_t shnum = elf16(48);
        uint16_t shentsize = elf16(46);

        uint64_t pltVaddr = 0;
        for (const auto& s : sections_)
            if (s.name == ".plt") { pltVaddr = s.virtualAddress; break; }

        uint64_t pltStubBase = 0, pltStubSize = 0;
        if (arch_ == "ARM") {
            std::tie(pltStubBase, pltStubSize) = armPltStubLayout();
        } else {
            uint64_t pltHeader;
            std::tie(pltHeader, pltStubSize) = pltLayout(arch_);
            pltStubBase = pltVaddr + pltHeader;
        }
        uint32_t jsType = jumpSlotRelocType(arch_);
        uint64_t stubIdx = 0;

        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;
            uint32_t type = elf32(secOffset + 4);
            if (type != 4 && type != 9) continue;

            uint32_t relOffset = elf32(secOffset + 16);
            uint32_t relSize = elf32(secOffset + 20);
            uint32_t entSize = elf32(secOffset + 36);
            if (entSize == 0) entSize = (type == 4) ? 12 : 8;
            uint32_t linkIdx = elf32(secOffset + 24);

            uint32_t strTabOffset = 0;
            if (linkIdx < shnum) {
                uint32_t lso = shoff + linkIdx * shentsize;
                uint32_t strIdx = elf32(lso + 24);
                if (strIdx < shnum) {
                    uint32_t strso = shoff + strIdx * shentsize;
                    strTabOffset = elf32(strso + 16);
                }
            }

            uint32_t numRels = relSize / entSize;
            for (uint32_t j = 0; j < numRels; ++j) {
                uint32_t rOffset = relOffset + j * entSize;
                if (rOffset + 8 > rawData_.size()) break;
                uint32_t rInfo = elf32(rOffset + 4);
                uint32_t symIdx = rInfo >> 8;
                uint32_t rType = rInfo & 0xFF;

                std::string symName;
                if (strTabOffset != 0 && linkIdx < shnum) {
                    uint32_t lso = shoff + linkIdx * shentsize;
                    uint32_t symTabOff = elf32(lso + 16);
                    uint32_t symEnt = elf32(lso + 36);
                    if (symEnt == 0) symEnt = 16;
                    uint32_t symOff = symTabOff + symIdx * symEnt;
                    if (symOff + 8 <= rawData_.size()) {
                        uint32_t nameIdx = elf32(symOff);
                        if (nameIdx != 0 && strTabOffset + nameIdx < rawData_.size()) {
                            symName = reinterpret_cast<const char*>(rawData_.data() + strTabOffset + nameIdx);
                        }
                    }
                }
                if (symName.empty() || symName == "(dynamic)") continue;

                uint32_t gotSlot = elf32(rOffset);

                if (rType == jsType) {
                    ImportInfo imp{};
                    imp.functionName = symName;
                    imp.address = gotSlot;
                    imports_.push_back(imp);

                    if (pltStubBase != 0 && pltStubSize > 0) {
                        ImportInfo stub{};
                        stub.functionName = symName;
                        stub.address = pltStubBase + stubIdx * pltStubSize;
                        imports_.push_back(stub);
                    }
                    stubIdx++;
                } else if (rType == 6 || rType == 21 || rType == 1 || rType == 20) {
                    ImportInfo imp{};
                    imp.functionName = symName;
                    imp.address = gotSlot;
                    imports_.push_back(imp);
                }
            }
        }
    }

    // GP-7056: stripped ELF recovery. With section headers absent (e_shoff ==
    // 0) the section-based passes (parseELFSymbols / parseELFImports /
    // parseELFRelocations) find nothing, so recover the loadable segments and
    // the dynamic imports from the program headers instead: PT_LOAD segments
    // become memory sections, PT_DYNAMIC yields DT_JMPREL / DT_RELA / DT_REL
    // relocation tables, the dynamic symbol table (DT_SYMTAB + DT_STRTAB)
    // names each relocated GOT slot, and the PLT stubs are located by
    // scanning the executable segments for the per-arch stub instruction
    // patterns.
    struct ElfPhdr {
        uint32_t type = 0;
        uint64_t vaddr = 0;
        uint64_t offset = 0;
        uint64_t filesz = 0;
        uint64_t memsz = 0;
        uint32_t flags = 0;
    };

    void parseELFProgramHeaders() {
        phdrs_.clear();
        if (bitness_ == 32) {
            uint32_t phoff = elf32(28);
            uint16_t phnum = elf16(44);
            uint16_t phentsize = elf16(42);
            if (phentsize == 0) phentsize = 32;
            for (uint16_t i = 0; i < phnum; ++i) {
                uint32_t o = phoff + i * phentsize;
                if (o + 32 > rawData_.size()) break;
                ElfPhdr p{};
                p.type = elf32(o);
                p.offset = elf32(o + 4);
                p.vaddr = elf32(o + 8);
                p.filesz = elf32(o + 16);
                p.memsz = elf32(o + 20);
                p.flags = elf32(o + 24);
                phdrs_.push_back(p);
            }
        } else {
            uint64_t phoff = elf64(32);
            uint16_t phnum = elf16(56);
            uint16_t phentsize = elf16(54);
            if (phentsize == 0) phentsize = 56;
            for (uint16_t i = 0; i < phnum; ++i) {
                uint64_t o = phoff + i * phentsize;
                if (o + 56 > rawData_.size()) break;
                ElfPhdr p{};
                p.type = elf32(o);
                p.flags = elf32(o + 4);
                p.offset = elf64(o + 8);
                p.vaddr = elf64(o + 16);
                p.filesz = elf64(o + 32);
                p.memsz = elf64(o + 40);
                phdrs_.push_back(p);
            }
        }
    }

    uint64_t phdrVaToFileOffset(uint64_t va) const {
        for (const auto& p : phdrs_) {
            if (p.type != 1) continue; // PT_LOAD
            if (va >= p.vaddr && va - p.vaddr < p.filesz) {
                return p.offset + (va - p.vaddr);
            }
        }
        return INVALID_FILE_OFFSET;
    }

    // x86/x86-64: locate the PLT stub whose `jmp [rip+disp32]` (FF 25, x86-64)
    // or `jmp [disp32]` (FF 25, x86) targets exactly this GOT slot.
    uint64_t findX86PltStub(uint64_t gotSlot) const {
        for (const auto& s : sections_) {
            if (!s.isExecutable || s.fileSize == 0 || s.fileOffset >= rawData_.size()) continue;
            const uint8_t* p = rawData_.data() + s.fileOffset;
            uint64_t n = std::min<uint64_t>(s.fileSize, rawData_.size() - s.fileOffset);
            for (uint64_t i = 0; i + 6 <= n; ++i) {
                if (p[i] != 0xFF || p[i + 1] != 0x25) continue;
                uint32_t u = static_cast<uint32_t>(p[i + 2]) |
                             (static_cast<uint32_t>(p[i + 3]) << 8) |
                             (static_cast<uint32_t>(p[i + 4]) << 16) |
                             (static_cast<uint32_t>(p[i + 5]) << 24);
                if (bitness_ == 32) {
                    if (u == gotSlot) return s.virtualAddress + i;
                } else {
                    int64_t target = s.virtualAddress + i + 6 +
                                     static_cast<int64_t>(static_cast<int32_t>(u));
                    if (static_cast<uint64_t>(target) == gotSlot) return s.virtualAddress + i;
                }
            }
        }
        return 0;
    }

    // ARM: every PLT stub starts with `add ip, pc, #imm` (0xe28fc600); the
    // first two matches in the executable segments give base + stride.
    std::pair<uint64_t, uint64_t> scanArmPlt() const {
        for (const auto& s : sections_) {
            if (!s.isExecutable || s.fileSize < 16 || s.fileOffset >= rawData_.size()) continue;
            std::vector<uint64_t> starts;
            const uint8_t* p = rawData_.data() + s.fileOffset;
            uint64_t n = std::min<uint64_t>(s.fileSize, rawData_.size() - s.fileOffset);
            for (uint64_t i = 4; i + 4 <= n; ++i) {
                bool match = elfBigEndian_
                    ? (p[i] == 0xe2 && p[i + 1] == 0x8f && p[i + 2] == 0xc6 && p[i + 3] == 0x00)
                    : (p[i] == 0x00 && p[i + 1] == 0xc6 && p[i + 2] == 0x8f && p[i + 3] == 0xe2);
                if (match) {
                    starts.push_back(s.virtualAddress + i);
                    if (starts.size() == 2) break;
                }
            }
            if (starts.size() >= 1)
                return {starts[0], starts.size() >= 2 ? starts[1] - starts[0] : 12};
        }
        return {0, 0};
    }

    // AARCH64: PLT stubs are 16-byte `adrp x16; ldr x17,[x16,#imm]; add
    // x16,x16,#imm; br x17` sequences. PLT0 itself starts with stp then the
    // same adrp/ldr/add/br at +4, so accept a base only when the next two
    // matches follow at 16-byte strides.
    std::pair<uint64_t, uint64_t> scanAarch64Plt() const {
        for (const auto& s : sections_) {
            if (!s.isExecutable || s.fileSize < 16 || s.fileOffset >= rawData_.size()) continue;
            std::vector<uint64_t> starts;
            const uint8_t* p = rawData_.data() + s.fileOffset;
            uint64_t n = std::min<uint64_t>(s.fileSize, rawData_.size() - s.fileOffset);
            for (uint64_t i = 0; i + 16 <= n; ++i) {
                uint32_t adrp = static_cast<uint32_t>(p[i]) |
                                (static_cast<uint32_t>(p[i + 1]) << 8) |
                                (static_cast<uint32_t>(p[i + 2]) << 16) |
                                (static_cast<uint32_t>(p[i + 3]) << 24);
                uint32_t ldr = static_cast<uint32_t>(p[i + 4]) |
                               (static_cast<uint32_t>(p[i + 5]) << 8) |
                               (static_cast<uint32_t>(p[i + 6]) << 16) |
                               (static_cast<uint32_t>(p[i + 7]) << 24);
                uint32_t br = static_cast<uint32_t>(p[i + 12]) |
                              (static_cast<uint32_t>(p[i + 13]) << 8) |
                              (static_cast<uint32_t>(p[i + 14]) << 16) |
                              (static_cast<uint32_t>(p[i + 15]) << 24);
                if ((adrp & 0x9F000000) != 0x90000000) continue; // adrp
                if ((adrp & 0x1F) != 0x10) continue;             // x16
                if ((ldr & 0x3B000000) != 0x39000000) continue;  // ldr (immediate), unsigned offset
                if ((ldr & 0xC0000000) != 0xC0000000) continue;  // 64-bit (x17)
                if ((ldr & 0x1F) != 0x11) continue;              // x17
                if (((ldr >> 5) & 0x1F) != 0x10) continue;       // [x16]
                if (br != 0xD61F0220) continue;                  // br x17
                starts.push_back(s.virtualAddress + i);
                if (starts.size() > 64) break;
            }
            for (size_t k = 0; k + 2 < starts.size(); ++k) {
                if (starts[k + 1] - starts[k] == 16 && starts[k + 2] - starts[k + 1] == 16)
                    return {starts[k], 16};
            }
            if (starts.size() >= 2) return {starts[0], starts[1] - starts[0]};
            if (starts.size() == 1) return {starts[0], 16};
        }
        return {0, 0};
    }

    // Task 2.3 / GP-7061: the GNU hash table (DT_GNU_HASH) is the modern
    // linker default and carries no explicit symbol count. Its header is
    // nbuckets, symoffset, bloom_size, bloom_shift followed by the bloom
    // filter (word-sized), the bucket table and the symbol-index chains
    // (terminated by a chain word with the low bit set). The exact dynamic
    // symbol count is the highest reachable symbol index plus one.
    uint64_t parseGnuHashSymCount(uint64_t hashOff) const {
        if (hashOff + 16 > rawData_.size()) return 0;
        uint32_t nbuckets = elf32(hashOff);
        uint32_t symoffset = elf32(hashOff + 4);
        uint32_t bloomSize = elf32(hashOff + 8);
        if (nbuckets == 0 || nbuckets > (1u << 22)) return 0;
        if (symoffset == 0 || symoffset > (1u << 22)) return 0;
        if (bloomSize > (1u << 20)) return 0;
        uint64_t wordSize = bitness_ == 32 ? 4 : 8;
        uint64_t bucketsOff = hashOff + 16 + static_cast<uint64_t>(bloomSize) * wordSize;
        uint64_t chainsOff = bucketsOff + static_cast<uint64_t>(nbuckets) * 4;
        uint64_t maxPos = 0;
        bool any = false;
        for (uint32_t b = 0; b < nbuckets; ++b) {
            if (bucketsOff + (static_cast<uint64_t>(b) + 1) * 4 > rawData_.size()) break;
            uint32_t bucket = elf32(bucketsOff + static_cast<uint64_t>(b) * 4);
            if (bucket < symoffset) continue;
            uint64_t pos = bucket - symoffset;
            for (uint64_t guard = 0; guard < (1u << 20); ++guard) {
                uint64_t co = chainsOff + pos * 4;
                if (co + 4 > rawData_.size()) break;
                if (pos > maxPos) maxPos = pos;
                any = true;
                if (elf32(co) & 1) break;
                ++pos;
            }
        }
        if (!any) return 0;
        uint64_t count = static_cast<uint64_t>(symoffset) + maxPos + 1;
        return count <= (1u << 22) ? count : 0;
    }

    void parseELFStripped() {
        parseELFProgramHeaders();
        if (phdrs_.empty()) return;

        // PT_LOAD segments become memory sections so populateProgram maps the
        // stripped image (readable unless a real R flag is known).
        int segIdx = 0;
        for (const auto& p : phdrs_) {
            if (p.type != 1 || p.memsz == 0) continue;
            SectionInfo sec{};
            sec.name = "seg_" + std::to_string(segIdx++);
            sec.virtualAddress = p.vaddr;
            sec.fileOffset = p.offset;
            sec.fileSize = p.filesz;
            sec.virtualSize = p.memsz;
            sec.isReadable = (p.flags & 0x4) != 0;
            sec.isWritable = (p.flags & 0x2) != 0;
            sec.isExecutable = (p.flags & 0x1) != 0;
            sections_.push_back(sec);
        }
        if (sections_.empty()) return;

        uint64_t dynVaddr = 0, dynSize = 0;
        for (const auto& p : phdrs_) {
            if (p.type == 2) { dynVaddr = p.vaddr; dynSize = p.filesz; break; }
        }
        if (dynVaddr == 0 || dynSize == 0) return;

        uint64_t dynOff = phdrVaToFileOffset(dynVaddr);
        if (dynOff == INVALID_FILE_OFFSET) return;

        struct DynTags {
            uint64_t strtab = 0, symtab = 0, syment = 0;
            uint64_t jmprel = 0, pltrelsz = 0, pltrel = 0;
            uint64_t rela = 0, relasz = 0, relaent = 0;
            uint64_t rel = 0, relsz = 0, relent = 0;
            uint64_t hash = 0, gnuhash = 0;   // DT_HASH / DT_GNU_HASH
            std::vector<uint64_t> needed;
        };
        DynTags tags;
        uint64_t ent = bitness_ == 32 ? 8 : 16;
        for (uint64_t i = 0; i + ent <= dynSize; i += ent) {
            uint64_t e = dynOff + i;
            if (e + ent > rawData_.size()) break;
            int64_t tag = bitness_ == 32 ? elfs32(e) : elfs64(e);
            uint64_t val = bitness_ == 32 ? elf32(e + 4) : elf64(e + 8);
            if (tag == 0) break;
            switch (tag) {
                case 1: tags.needed.push_back(val); break;   // DT_NEEDED
                case 2: tags.pltrelsz = val; break;          // DT_PLTRELSZ
                case 4: tags.hash = val; break;              // DT_HASH
                case 5: tags.strtab = val; break;            // DT_STRTAB
                case 6: tags.symtab = val; break;            // DT_SYMTAB
                case 7: tags.rela = val; break;              // DT_RELA
                case 8: tags.relasz = val; break;            // DT_RELASZ
                case 9: tags.relaent = val; break;           // DT_RELAENT
                case 11: tags.syment = val; break;           // DT_SYMENT
                case 17: tags.rel = val; break;              // DT_REL
                case 18: tags.relsz = val; break;            // DT_RELSZ
                case 19: tags.relent = val; break;           // DT_RELENT
                case 20: tags.pltrel = val; break;           // DT_PLTREL (7=RELA,17=REL)
                case 23: tags.jmprel = val; break;           // DT_JMPREL
                case 0x6FFFFEF5: tags.gnuhash = val; break;  // DT_GNU_HASH
            }
        }
        if (tags.strtab == 0 || tags.symtab == 0) return;
        if (tags.syment == 0) tags.syment = bitness_ == 32 ? 16 : 24;
        if (tags.relaent == 0) tags.relaent = bitness_ == 32 ? 12 : 24;
        if (tags.relent == 0) tags.relent = bitness_ == 32 ? 8 : 16;

        uint64_t strOff = phdrVaToFileOffset(tags.strtab);
        uint64_t symOff = phdrVaToFileOffset(tags.symtab);
        if (strOff == INVALID_FILE_OFFSET || symOff == INVALID_FILE_OFFSET) return;

        // Dynamic libraries (DT_NEEDED), same shape as the section path.
        for (uint64_t nIdx : tags.needed) {
            std::string libName;
            if (nIdx != 0 && strOff + nIdx < rawData_.size()) {
                libName = reinterpret_cast<const char*>(rawData_.data() + strOff + nIdx);
            }
            if (libName.empty()) continue;
            ImportInfo imp{};
            imp.libraryName = libName;
            imp.functionName = "(dynamic)";
            imp.address = 0;
            imports_.push_back(imp);
        }

        // Dynamic symbol table: size it from the largest relocation symbol
        // index (there is no DT_SYMSZ tag).
        uint64_t maxSymIdx = 0;
        auto scanForMaxSym = [&](uint64_t rva, uint64_t size, uint64_t rEnt) {
            uint64_t off = phdrVaToFileOffset(rva);
            if (off == INVALID_FILE_OFFSET || rEnt == 0) return;
            uint64_t cnt = size / rEnt;
            for (uint64_t j = 0; j < cnt; ++j) {
                uint64_t e = off + j * rEnt;
                if (e + (bitness_ == 32 ? 8 : 16) > rawData_.size()) break;
                if (bitness_ == 32) {
                    maxSymIdx = std::max<uint64_t>(maxSymIdx, elf32(e + 4) >> 8);
                } else {
                    maxSymIdx = std::max<uint64_t>(maxSymIdx, elf64(e + 8) >> 32);
                }
            }
        };
        if (tags.jmprel != 0 && tags.pltrelsz != 0) {
            scanForMaxSym(tags.jmprel, tags.pltrelsz,
                          tags.pltrel == 7 ? tags.relaent : tags.relent);
        }
        if (tags.rela != 0 && tags.relasz != 0) scanForMaxSym(tags.rela, tags.relasz, tags.relaent);
        if (tags.rel != 0 && tags.relsz != 0) scanForMaxSym(tags.rel, tags.relsz, tags.relent);

        // Task 2.3 / GP-7061: size the dynamic symbol table exactly from the
        // GNU hash table (DT_GNU_HASH, the default for modern Linux linkers)
        // or the SYSV hash table (DT_HASH, nchain at +4) when present, so
        // symbols not referenced by any relocation are included; otherwise
        // fall back to the largest relocation symbol index.
        uint64_t dynSymCount = 0;
        if (tags.gnuhash != 0) {
            uint64_t hashOff = phdrVaToFileOffset(tags.gnuhash);
            if (hashOff != INVALID_FILE_OFFSET) dynSymCount = parseGnuHashSymCount(hashOff);
        }
        if (dynSymCount == 0 && tags.hash != 0) {
            uint64_t hashOff = phdrVaToFileOffset(tags.hash);
            if (hashOff != INVALID_FILE_OFFSET && hashOff + 8 <= rawData_.size()) {
                uint32_t nchain = elf32(hashOff + 4);
                if (nchain > 0 && nchain <= (1u << 22)) dynSymCount = nchain;
            }
        }
        if (dynSymCount == 0) dynSymCount = maxSymIdx + 1;

        std::vector<std::string> symNames(dynSymCount);
        for (uint64_t j = 0; j < dynSymCount; ++j) {
            uint64_t e = symOff + j * tags.syment;
            if (e + (bitness_ == 32 ? 16 : 24) > rawData_.size()) break;
            uint32_t nameIdx = elf32(e);
            if (nameIdx != 0 && strOff + nameIdx < rawData_.size()) {
                symNames[j] = reinterpret_cast<const char*>(rawData_.data() + strOff + nameIdx);
            }
        }

        // Task 2.3 / GP-6887: populate the defined dynamic symbols (mirrors
        // parseELF64Symbols / parseELF32Symbols: skip name-less and value-0
        // entries; external iff GLOBAL/WEAK binding and SHN_UNDEF).
        for (uint64_t j = 1; j < dynSymCount; ++j) {
            uint64_t e = symOff + j * tags.syment;
            if (e + (bitness_ == 32 ? 16 : 24) > rawData_.size()) break;
            uint32_t nameIdx = elf32(e);
            uint64_t value, size;
            uint8_t bind, stype;
            uint16_t shndx;
            if (bitness_ == 32) {
                value = elf32(e + 4);
                size = elf32(e + 8);
                uint8_t info = rawData_[e + 12];
                bind = info >> 4;
                stype = info & 0xF;
                shndx = elf16(e + 14);
            } else {
                uint8_t info = rawData_[e + 4];
                bind = info >> 4;
                stype = info & 0xF;
                shndx = elf16(e + 6);
                value = elf64(e + 8);
                size = elf64(e + 16);
            }
            if (nameIdx == 0 || value == 0) continue;
            if (strOff + nameIdx >= rawData_.size()) continue;
            std::string name =
                reinterpret_cast<const char*>(rawData_.data() + strOff + nameIdx);
            if (name.empty()) continue;
            SymbolInfo sym{};
            sym.name = name;
            sym.address = value;
            sym.size = size;
            sym.isFunction = (stype == 2);
            sym.isExternal = (bind == 1 || bind == 2) && shndx == 0;
            symbols_.push_back(sym);
        }

        // Relocations: JUMP_SLOT names the GOT slot + PLT stub, GLOB_DAT and
        // friends name the GOT slot only (mirrors the section-based passes).
        uint32_t jsType = jumpSlotRelocType(arch_);
        uint64_t stubIdx = 0;
        bool pltScanned = false;
        uint64_t pltStubBase = 0, pltStubSize = 0;
        auto findPltStub = [&](uint64_t gotSlot, uint64_t idx) -> uint64_t {
            if (arch_ == "x86") return findX86PltStub(gotSlot);
            if (!pltScanned) {
                pltScanned = true;
                if (arch_ == "ARM") {
                    std::tie(pltStubBase, pltStubSize) = scanArmPlt();
                } else if (arch_ == "AARCH64") {
                    std::tie(pltStubBase, pltStubSize) = scanAarch64Plt();
                }
            }
            if (pltStubBase == 0 || pltStubSize == 0) return 0;
            return pltStubBase + idx * pltStubSize;
        };
        auto isGlobDat = [&](uint32_t t) {
            if (t == 6 || t == 1 || t == 20 || t == 21) return true; // GLOB_DAT / ABS / PPC / ARM
            return bitness_ == 64 && t == 0x401;                     // AARCH64 GLOB_DAT
        };
        auto emitRelocs = [&](uint64_t rva, uint64_t size, uint64_t rEnt, bool rela) {
            uint64_t off = phdrVaToFileOffset(rva);
            if (off == INVALID_FILE_OFFSET || rEnt == 0) return;
            uint64_t cnt = size / rEnt;
            for (uint64_t j = 0; j < cnt; ++j) {
                uint64_t e = off + j * rEnt;
                if (e + (bitness_ == 32 ? 8 : 16) > rawData_.size()) break;
                uint64_t rOffset;
                uint64_t symIdx;
                uint32_t rType;
                if (bitness_ == 32) {
                    rOffset = elf32(e);
                    uint32_t info = elf32(e + 4);
                    symIdx = info >> 8;
                    rType = info & 0xFF;
                } else {
                    rOffset = elf64(e);
                    uint64_t info = elf64(e + 8);
                    symIdx = info >> 32;
                    rType = static_cast<uint32_t>(info & 0xFFFFFFFF);
                }
                if (symIdx >= symNames.size()) continue;
                const std::string& symName = symNames[symIdx];
                if (symName.empty() || symName == "(dynamic)") continue;
                if (rType == jsType) {
                    ImportInfo imp{};
                    imp.functionName = symName;
                    imp.address = rOffset;
                    imports_.push_back(imp);
                    uint64_t stub = findPltStub(rOffset, stubIdx);
                    if (stub != 0) {
                        ImportInfo s{};
                        s.functionName = symName;
                        s.address = stub;
                        imports_.push_back(s);
                    }
                    stubIdx++;
                } else if (isGlobDat(rType)) {
                    ImportInfo imp{};
                    imp.functionName = symName;
                    imp.address = rOffset;
                    imports_.push_back(imp);
                }
            }
        };
        if (tags.jmprel != 0 && tags.pltrelsz != 0) {
            emitRelocs(tags.jmprel, tags.pltrelsz,
                       tags.pltrel == 7 ? tags.relaent : tags.relent,
                       tags.pltrel == 7);
        }
        if (tags.rela != 0 && tags.relasz != 0) emitRelocs(tags.rela, tags.relasz, tags.relaent, true);
        if (tags.rel != 0 && tags.relsz != 0) emitRelocs(tags.rel, tags.relsz, tags.relent, false);
    }

    bool parseFatMachO() {
        if (rawData_.size() < 12) return false;

        uint32_t nfat_arch = *reinterpret_cast<uint32_t*>(rawData_.data() + 4);
        if (nfat_arch == 0 || nfat_arch > 16) return false;

        // Architecture preference order
        static const uint32_t PREFERRED_CPUS[] = {
            0x01000007, // x86_64
            7,          // x86 (32-bit)
            0x0100000C, // AARCH64 (arm64)
            12,         // ARM (32-bit)
            0x01000012, // PPC64
            18,         // PPC
        };

        uint32_t bestOffset = 0, bestSize = 0;
        bool found = false;

        // Start with the first arch as fallback
        if (nfat_arch > 0) {
            bestOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + 8);
            bestSize = *reinterpret_cast<uint32_t*>(rawData_.data() + 12);
            found = true;
        }

        // Iterate to find best match
        for (uint32_t i = 0; i < nfat_arch; i++) {
            uint32_t entryOffset = 8 + i * 20;
            if (entryOffset + 20 > rawData_.size()) break;

            uint32_t cputype = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset);
            uint32_t offset = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset + 8);
            uint32_t size = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset + 12);

            if (offset + size > rawData_.size()) continue;

            // Check if this is our preferred architecture
            for (auto pref : PREFERRED_CPUS) {
                if (cputype == pref) {
                    bestOffset = offset;
                    bestSize = size;
                    found = true;
                    goto extracted;
                }
            }
        }
        extracted:
        if (!found || bestOffset == 0 || bestSize == 0) return false;

        // Extract the thin Mach-O into rawData_ and parse it
        std::vector<uint8_t> thinData(rawData_.begin() + bestOffset,
                                       rawData_.begin() + bestOffset + bestSize);

        // Check thin Mach-O magic
        if (thinData.size() < 8) return false;
        uint32_t thinMagic = *reinterpret_cast<uint32_t*>(thinData.data());
        if (thinMagic != 0xCEFAEDFE && thinMagic != 0xCFFAEDFE) return false;

        rawData_ = std::move(thinData);
        return parseMachO();
    }

    // Task 2.5 / GP-7079: dyld shared cache support.  The cache is parsed as
    // one section per mapping plus an image table (dyld_cache_image_info);
    // loadDyldCacheImage() then re-parses a single dylib's embedded Mach-O so
    // analysis can target individual images (GUI picker deferred to G2).
    bool parseDyldCache() {
        const size_t sz = rawData_.size();
        if (sz < 0x50) return false;
        const uint32_t magic = *reinterpret_cast<uint32_t*>(rawData_.data());
        const bool isNewHeader = (magic == 0x6A1A64A9);
        const uint32_t mappingOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + 4);
        const uint32_t mappingCount = *reinterpret_cast<uint32_t*>(rawData_.data() + 8);
        const uint32_t imagesOffset = isNewHeader
            ? *reinterpret_cast<uint32_t*>(rawData_.data() + 0x40)
            : *reinterpret_cast<uint32_t*>(rawData_.data() + 0x0C);
        const uint32_t imagesCount = isNewHeader
            ? *reinterpret_cast<uint32_t*>(rawData_.data() + 0x44)
            : *reinterpret_cast<uint32_t*>(rawData_.data() + 0x10);
        const uint64_t dyldBase = *reinterpret_cast<uint64_t*>(rawData_.data() + 0x18);

        if (mappingOffset == 0 || mappingCount == 0 || mappingCount > 1024) return false;
        if (static_cast<uint64_t>(mappingOffset) + mappingCount * 32ULL > sz) return false;

        formatName_ = "Mach-O dyld Shared Cache";
        bitness_ = 64;
        isDyldCache_ = true;
        imageBase_ = dyldBase;
        arch_ = "AARCH64";

        for (uint32_t i = 0; i < mappingCount; i++) {
            const uint32_t m = mappingOffset + i * 32;
            const uint64_t addr = *reinterpret_cast<uint64_t*>(rawData_.data() + m);
            const uint64_t size = *reinterpret_cast<uint64_t*>(rawData_.data() + m + 8);
            const uint64_t foff = *reinterpret_cast<uint64_t*>(rawData_.data() + m + 16);
            const uint32_t prot = *reinterpret_cast<uint32_t*>(rawData_.data() + m + 28);
            if (size == 0) continue;
            SectionInfo sec{};
            sec.name = "mapping_" + std::to_string(i);
            sec.virtualAddress = addr;
            sec.virtualSize = size;
            sec.fileOffset = foff;
            sec.fileSize = (foff < sz) ? std::min<uint64_t>(size, sz - foff) : 0;
            sec.isReadable = true;
            sec.isWritable = (prot & 0x02) != 0;
            sec.isExecutable = (prot & 0x04) != 0;
            sections_.push_back(sec);
        }
        if (sections_.empty()) return false;

        // Cache vm address -> file offset via the mapping table
        auto cacheAddrToFileOffset = [&](uint64_t addr) -> uint64_t {
            for (const auto& sec : sections_) {
                if (addr >= sec.virtualAddress && addr < sec.virtualAddress + sec.virtualSize)
                    return sec.fileOffset + (addr - sec.virtualAddress);
            }
            return 0;
        };

        if (imagesOffset != 0 && imagesCount != 0 && imagesCount < 0x10000) {
            for (uint32_t i = 0; i < imagesCount; i++) {
                if (static_cast<uint64_t>(imagesOffset) + (i + 1ULL) * 32 > sz) break;
                const uint32_t im = imagesOffset + i * 32;
                const uint64_t addr = *reinterpret_cast<uint64_t*>(rawData_.data() + im);
                const uint32_t pathOff = *reinterpret_cast<uint32_t*>(rawData_.data() + im + 24);
                if (pathOff >= sz) continue;
                std::string name = reinterpret_cast<const char*>(rawData_.data() + pathOff);
                size_t n = name.find('\0');
                if (n != std::string::npos) name.resize(n);
                if (name.empty()) continue;
                DyldCacheImageInfo img{};
                img.name = name;
                img.address = addr;
                img.fileOffset = cacheAddrToFileOffset(addr);
                dyldCacheImages_.push_back(img);
            }
        }

        // Refine the architecture from the first image's Mach-O header
        if (!dyldCacheImages_.empty() &&
            dyldCacheImages_[0].fileOffset + 8 <= sz) {
            const uint32_t cputype = *reinterpret_cast<uint32_t*>(
                rawData_.data() + dyldCacheImages_[0].fileOffset + 4);
            if (cputype == 0x01000007 || cputype == 7) arch_ = "x86";
            else if (cputype == 0x0100000C || cputype == 12) arch_ = "AARCH64";
        }

        return true;
    }

    bool loadDyldCacheImage(const std::string& name) override {
        if (!isDyldCache_) return false;
        const DyldCacheImageInfo* img = nullptr;
        for (const auto& i : dyldCacheImages_) {
            if (i.name == name) { img = &i; break; }
        }
        if (!img || img->fileOffset >= rawData_.size()) return false;

        // Size the carve-out to the end of the containing mapping
        uint64_t endOff = rawData_.size();
        for (const auto& sec : sections_) {
            if (img->fileOffset >= sec.fileOffset &&
                img->fileOffset < sec.fileOffset + sec.fileSize)
                endOff = sec.fileOffset + sec.fileSize;
        }
        if (endOff <= img->fileOffset) return false;

        std::vector<uint8_t> sub(rawData_.begin() + static_cast<size_t>(img->fileOffset),
                                 rawData_.begin() + static_cast<size_t>(endOff));
        std::vector<uint8_t> saved = std::move(rawData_);
        rawData_ = std::move(sub);

        sections_.clear();
        symbols_.clear();
        imports_.clear();
        exports_.clear();
        relocations_.clear();
        machoSegments_.clear();
        machoDylibNames_.clear();
        machONlistNames_.clear();
        entryPoint_ = 0;
        imageBase_ = 0;
        cpusubtype_ = 0;
        dysymtabIndirectSymOffset_ = 0;
        dysymtabIndirectSymCount_ = 0;
        chainedFixupsOff_ = 0;
        chainedFixupsSize_ = 0;
        machoTextAddr_ = 0;

        bool ok = parseMachO();
        rawData_ = std::move(saved);
        return ok;
    }

    bool parseMachO() {
        uint32_t magic = *reinterpret_cast<uint32_t*>(rawData_.data());
        bool is64 = (magic == 0xCFFAEDFE);
        return is64 ? parseMachO64() : parseMachO32();
    }

    bool parseMachO32() {
        formatName_ = "Mac OS X Mach-O";
        if (rawData_.size() < 28) return false;
        if (rawData_.size() < 28) return false;

        uint32_t cputype = *reinterpret_cast<uint32_t*>(rawData_.data() + 4);
        cpusubtype_ = *reinterpret_cast<uint32_t*>(rawData_.data() + 8);
        uint32_t ncmds = *reinterpret_cast<uint32_t*>(rawData_.data() + 16);
        uint32_t sizeofcmds = *reinterpret_cast<uint32_t*>(rawData_.data() + 20);

        bitness_ = 32;
        switch (cputype) {
            case 7: arch_ = "x86"; break;
            case 12: arch_ = "ARM"; break;
            case 18: arch_ = "PowerPC"; break;
            default: arch_ = "unknown"; break;
        }

        // Default entry via LC_MAIN offset
        uint64_t entryOff = 0;

        uint32_t cmdOffset = 28; // after mach_header (28 bytes for 32-bit)
        uint32_t cmdEnd = cmdOffset + sizeofcmds;
        while (cmdOffset + 8 <= cmdEnd && cmdOffset + 8 <= rawData_.size()) {
            uint32_t cmd = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset);
            uint32_t cmdsize = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 4);
            if (cmdsize < 8) break;

            switch (cmd) {
                case 0x01: { // LC_SEGMENT
                    uint32_t nsects = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 48);
                    uint32_t segFileOff = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 32);
                    uint32_t segFileSize = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 36);
                    uint32_t segVMAddr = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 24);
                    uint32_t segVMSize = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 28);

                    // First segment's vmaddr is usually the image base
                    if (imageBase_ == 0) imageBase_ = segVMAddr;

                    {
                        MachOSegInfo segInfo{};
                        char segNameBuf[17] = {};
                        std::memcpy(segNameBuf, rawData_.data() + cmdOffset + 8, 16);
                        segInfo.name = segNameBuf;
                        segInfo.vmaddr = segVMAddr;
                        segInfo.fileoff = segFileOff;
                        machoSegments_.push_back(segInfo);
                    }

                    uint32_t sectionOffset = cmdOffset + 56; // after segment_command (56 bytes)
                    for (uint32_t i = 0; i < nsects; i++) {
                        if (sectionOffset + 68 > rawData_.size()) break;
                        parseMachOSection32(sectionOffset, segVMAddr);
                        sectionOffset += 68;
                    }
                    break;
                }
                case 0x02: { // LC_SYMTAB
                    uint32_t symoff = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 8);
                    uint32_t nsyms = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 12);
                    uint32_t stroff = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 16);
                    uint32_t strsize = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 20);
                    parseMachONlist32(symoff, nsyms, stroff, strsize);
                    break;
                }
                case 0x0B: { // LC_DYSYMTAB (32-bit)
                    if (cmdsize >= 80 && cmdOffset + 80 <= rawData_.size()) {
                        dysymtabIndirectSymOffset_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 56);
                        dysymtabIndirectSymCount_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 60);
                    }
                    break;
                }
                case 0x0C: { // LC_LOAD_DYLIB
                    uint32_t nameOffset = cmdOffset + 24;
                    if (nameOffset < rawData_.size()) {
                        std::string libName = reinterpret_cast<const char*>(rawData_.data() + nameOffset);
                        size_t libLen = libName.find('\0');
                        if (libLen != std::string::npos) libName.resize(libLen);
                        if (!libName.empty()) {
                            machoDylibNames_.push_back(libName);
                            ImportInfo imp{};
                            imp.libraryName = libName;
                            imp.functionName = "(dynamic)";
                            imp.address = 0;
                            imports_.push_back(imp);
                        }
                    }
                    break;
                }
                case 0x28: { // LC_MAIN
                    if (cmdOffset + 16 <= rawData_.size()) {
                        uint64_t entryoff = *reinterpret_cast<uint64_t*>(rawData_.data() + cmdOffset + 8);
                        entryOff = entryoff;
                    }
                    break;
                }
                case 0x34: { // LC_DYLD_CHAINED_FIXUPS
                    if (cmdOffset + 24 <= rawData_.size()) {
                        chainedFixupsOff_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 8);
                        chainedFixupsSize_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 16);
                    }
                    break;
                }
            }
            cmdOffset += cmdsize;
        }

        // Chained fixup rebases are relative to the image start (__TEXT).
        machoTextAddr_ = 0;
        for (const auto& mseg : machoSegments_) {
            if (mseg.name == "__TEXT") { machoTextAddr_ = mseg.vmaddr; break; }
        }

        if (chainedFixupsOff_ != 0 && chainedFixupsSize_ != 0)
            parseMachOChainedFixups(4);

        resolveMachOImports(bitness_ == 64 ? 8 : 4);

        if (entryOff != 0) {
            // entryOff is a file offset; convert to VM address
            for (const auto& sec : sections_) {
                uint64_t secFileOff = sec.fileOffset;
                uint64_t secFileEnd = secFileOff + sec.fileSize;
                if (entryOff >= secFileOff && entryOff < secFileEnd) {
                    entryPoint_ = sec.virtualAddress + (entryOff - secFileOff);
                    break;
                }
            }
            if (entryPoint_ == 0)
                entryPoint_ = imageBase_ + entryOff;
        }

        return true;
    }

    bool parseMachO64() {
        formatName_ = "Mac OS X Mach-O";
        if (rawData_.size() < 32) return false;

        uint32_t cputype = *reinterpret_cast<uint32_t*>(rawData_.data() + 4);
        cpusubtype_ = *reinterpret_cast<uint32_t*>(rawData_.data() + 8);
        uint32_t ncmds = *reinterpret_cast<uint32_t*>(rawData_.data() + 16);
        uint32_t sizeofcmds = *reinterpret_cast<uint32_t*>(rawData_.data() + 20);

        bitness_ = 64;
        switch (cputype) {
            case 0x01000007: arch_ = "x86"; break;
            case 0x0100000C: arch_ = "AARCH64"; break;
            case 0x01000012: arch_ = "PowerPC"; break;
            case 7: arch_ = "x86"; break;
            case 12: arch_ = "ARM"; break;
            default: arch_ = "unknown"; break;
        }

        uint64_t entryOff = 0;

        uint32_t cmdOffset = 32; // after mach_header_64
        uint32_t cmdEnd = cmdOffset + sizeofcmds;
        while (cmdOffset + 8 <= cmdEnd && cmdOffset + 8 <= rawData_.size()) {
            uint32_t cmd = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset);
            uint32_t cmdsize = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 4);
            if (cmdsize < 8) break;

            switch (cmd) {
                case 0x19: { // LC_SEGMENT_64
                    uint32_t nsects = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 64);
                    uint64_t segFileOff = *reinterpret_cast<uint64_t*>(rawData_.data() + cmdOffset + 40);
                    uint64_t segFileSize = *reinterpret_cast<uint64_t*>(rawData_.data() + cmdOffset + 48);
                    uint64_t segVMAddr = *reinterpret_cast<uint64_t*>(rawData_.data() + cmdOffset + 24);
                    uint64_t segVMSize = *reinterpret_cast<uint64_t*>(rawData_.data() + cmdOffset + 32);

                    if (imageBase_ == 0) imageBase_ = segVMAddr;

                    {
                        MachOSegInfo segInfo{};
                        char segNameBuf[17] = {};
                        std::memcpy(segNameBuf, rawData_.data() + cmdOffset + 8, 16);
                        segInfo.name = segNameBuf;
                        segInfo.vmaddr = segVMAddr;
                        segInfo.fileoff = segFileOff;
                        machoSegments_.push_back(segInfo);
                    }

                    uint32_t sectionOffset = cmdOffset + 72; // after segment_command_64
                    for (uint32_t i = 0; i < nsects; i++) {
                        if (sectionOffset + 80 > rawData_.size()) break;
                        parseMachOSection64(sectionOffset, segVMAddr);
                        sectionOffset += 80;
                    }
                    break;
                }
                case 0x02: { // LC_SYMTAB
                    uint32_t symoff = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 8);
                    uint32_t nsyms = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 12);
                    uint32_t stroff = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 16);
                    uint32_t strsize = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 20);
                    parseMachONlist64(symoff, nsyms, stroff, strsize);
                    break;
                }
                case 0x0B: { // LC_DYSYMTAB (64-bit)
                    if (cmdsize >= 80 && cmdOffset + 80 <= rawData_.size()) {
                        dysymtabIndirectSymOffset_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 56);
                        dysymtabIndirectSymCount_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 60);
                    }
                    break;
                }
                case 0x0C: { // LC_LOAD_DYLIB (64-bit)
                    uint32_t nameOffset = cmdOffset + 24;
                    if (nameOffset < rawData_.size()) {
                        std::string libName = reinterpret_cast<const char*>(rawData_.data() + nameOffset);
                        size_t libLen = libName.find('\0');
                        if (libLen != std::string::npos) libName.resize(libLen);
                        if (!libName.empty()) {
                            machoDylibNames_.push_back(libName);
                            ImportInfo imp{};
                            imp.libraryName = libName;
                            imp.functionName = "(dynamic)";
                            imp.address = 0;
                            imports_.push_back(imp);
                        }
                    }
                    break;
                }
                case 0x28: { // LC_MAIN
                    if (cmdOffset + 16 <= rawData_.size()) {
                        uint64_t entryoff = *reinterpret_cast<uint64_t*>(rawData_.data() + cmdOffset + 8);
                        entryOff = entryoff;
                    }
                    break;
                }
                case 0x34: { // LC_DYLD_CHAINED_FIXUPS
                    if (cmdOffset + 24 <= rawData_.size()) {
                        chainedFixupsOff_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 8);
                        chainedFixupsSize_ = *reinterpret_cast<uint32_t*>(rawData_.data() + cmdOffset + 16);
                    }
                    break;
                }
            }
            cmdOffset += cmdsize;
        }

        // Chained fixup rebases are relative to the image start (__TEXT).
        machoTextAddr_ = 0;
        for (const auto& mseg : machoSegments_) {
            if (mseg.name == "__TEXT") { machoTextAddr_ = mseg.vmaddr; break; }
        }

        if (chainedFixupsOff_ != 0 && chainedFixupsSize_ != 0)
            parseMachOChainedFixups(8);

        resolveMachOImports(bitness_ == 64 ? 8 : 4);

        if (entryOff != 0) {
            for (const auto& sec : sections_) {
                uint64_t secFileOff = sec.fileOffset;
                uint64_t secFileEnd = secFileOff + sec.fileSize;
                if (entryOff >= secFileOff && entryOff < secFileEnd) {
                    entryPoint_ = sec.virtualAddress + (entryOff - secFileOff);
                    break;
                }
            }
            if (entryPoint_ == 0)
                entryPoint_ = imageBase_ + entryOff;
        }

        return true;
    }

    static bool isIndirectSymbolSection(const std::string& name) {
        return name == "__la_symbol_ptr" || name == "__nl_symbol_ptr" ||
               name == "__got" || name == "__stubs" ||
               name == "__symbol_ptr" || name == "__lazy_symbol_ptr";
    }

    void resolveMachOImports(int ptrSize) {
        if (dysymtabIndirectSymCount_ == 0 || machONlistNames_.empty()) return;
        if (dysymtabIndirectSymOffset_ >= rawData_.size()) return;

        // Read indirect symbol table (clamped to the file, GP-7046)
        const uint32_t* indirectTable = reinterpret_cast<const uint32_t*>(
            rawData_.data() + dysymtabIndirectSymOffset_);
        uint32_t tableCount = dysymtabIndirectSymCount_;
        uint64_t tableBytes = static_cast<uint64_t>(tableCount) * 4;
        if (tableBytes > rawData_.size() - dysymtabIndirectSymOffset_)
            tableCount = static_cast<uint32_t>((rawData_.size() - dysymtabIndirectSymOffset_) / 4);
        if (tableCount == 0) return;

        for (const auto& sec : sections_) {
            if (!isIndirectSymbolSection(sec.name)) continue;

            uint32_t startIndex = sec.reserved1;
            uint32_t count = static_cast<uint32_t>(sec.virtualSize / ptrSize);
            if (count == 0) continue;
            if (startIndex + count > tableCount) count = tableCount - startIndex;

            for (uint32_t i = 0; i < count; i++) {
                uint32_t symIndex = indirectTable[startIndex + i];
                // INDIRECT_SYMBOL_LOCAL=0 and INDIRECT_SYMBOL_ABS=1 are special
                if (symIndex < 2) continue;
                // Adjust for the 2-special-value offset
                uint32_t adjustedIndex = symIndex - 2;
                if (adjustedIndex >= machONlistNames_.size()) continue;

                const std::string& funcName = machONlistNames_[adjustedIndex];
                if (funcName.empty()) continue;

                uint64_t stubAddr = sec.virtualAddress + i * ptrSize;

                // Check if this import already exists (from nlist parsing)
                bool exists = false;
                for (const auto& imp : imports_) {
                    if (imp.address == stubAddr) {
                        exists = true;
                        break;
                    }
                }
                if (exists) continue;

                ImportInfo imp{};
                imp.functionName = funcName;
                imp.address = stubAddr;
                imports_.push_back(imp);
            }
        }
    }

    // Task 2.5 / GP-7046: Apple chained fixups (LC_DYLD_CHAINED_FIXUPS, 0x34).
    // Decodes the dyld_chained_fixups_header blob and walks every chained
    // pointer chain in each segment's pages:
    //   - rebases resolve to the unslid vm address and are patched into the
    //     in-memory bytes (mirrors the COFF reloc-patch approach) so
    //     disassembly sees real pointer values;
    //   - binds resolve through dyld_chained_import entries to symbol names
    //     and surface as imports addressed at their chain location (the
    //     slot is nulled since the foreign symbol's address is unknown).
    // Pointer formats: DYLD_CHAINED_PTR_64 (1), _64_OFFSET (2),
    // _ARM64E (7), _ARM64E_USERLAND (8), _ARM64E_USERLAND24 (12).
    // Field layouts follow Apple's fixup-chains.h: bind = MSB, next is a
    // stride count (4-byte units for 64/64_OFFSET, 8-byte for ARM64E).
    void parseMachOChainedFixups(int ptrSize) {
        const size_t sz = rawData_.size();
        const uint32_t base = chainedFixupsOff_;
        if (base == 0 || base + 28 > sz) return;

        auto rd16 = [&](size_t o) -> uint16_t {
            if (o + 2 > sz) return 0;
            return *reinterpret_cast<const uint16_t*>(rawData_.data() + o);
        };
        auto rd32 = [&](size_t o) -> uint32_t {
            if (o + 4 > sz) return 0;
            return *reinterpret_cast<const uint32_t*>(rawData_.data() + o);
        };
        auto rd64 = [&](size_t o) -> uint64_t {
            if (o + 8 > sz) return 0;
            return *reinterpret_cast<const uint64_t*>(rawData_.data() + o);
        };

        const uint32_t startsOff = rd32(base + 4);
        const uint32_t importsOff = rd32(base + 8);
        const uint32_t symbolsOff = rd32(base + 12);
        const uint32_t importsCount = rd32(base + 16);
        const uint32_t importsFormat = rd32(base + 20);
        if (startsOff == 0 || importsFormat == 0 || importsFormat > 3) return;

        // dyld_chained_import / _addend / _addend64 table
        struct ChainImport {
            uint32_t nameOffset; // into the fixups blob's symbol strings
            int32_t libraryOrdinal; // 1-based positive, -1 self, -2 flat
        };
        std::vector<ChainImport> chImports;
        {
            size_t entrySize = (importsFormat == 1) ? 4 : (importsFormat == 2) ? 8 : 16;
            uint32_t impBase = base + importsOff;
            for (uint32_t i = 0; i < importsCount && importsCount < 0x10000; i++) {
                if (static_cast<uint64_t>(impBase) + (i + 1ULL) * entrySize > sz) break;
                ChainImport ci{};
                if (importsFormat == 1 || importsFormat == 2) {
                    uint32_t v = importsFormat == 1 ? rd32(impBase + i * 4)
                                                    : static_cast<uint32_t>(rd64(impBase + i * 8));
                    ci.libraryOrdinal = static_cast<int8_t>(v & 0xFF);
                    ci.nameOffset = (v >> 9) & 0x7FFFFF;
                } else {
                    uint64_t v = rd64(impBase + i * 16);
                    ci.libraryOrdinal = static_cast<int16_t>(v & 0xFFFF);
                    ci.nameOffset = rd32(impBase + i * 16 + 4);
                }
                chImports.push_back(ci);
            }
        }

        // dyld_chained_starts_in_image: seg_count + per-segment offsets
        const uint32_t starts = base + startsOff;
        if (starts + 4 > sz) return;
        const uint32_t segCount = rd32(starts);
        if (segCount == 0 || segCount > 64) return;
        if (static_cast<uint64_t>(starts) + 4 + segCount * 4ULL > sz) return;

        // vm address of the image start (__TEXT segment), used for rebasing
        uint64_t textAddr = machoTextAddr_;
        if (textAddr == 0) {
            if (!machoSegments_.empty()) textAddr = machoSegments_[0].vmaddr;
            else textAddr = imageBase_;
        }
        if (textAddr == 0) return;

        auto processChainPointer = [&](uint64_t locOff, uint16_t pointerFormat,
                                       uint64_t segVmaddr, uint64_t segFileoff) -> uint64_t {
            // locOff: file offset of the encoded pointer; returns the file
            // offset of the next pointer in the chain (0 = chain ended)
            if (locOff + static_cast<uint64_t>(ptrSize) > sz) return 0;
            const uint64_t raw = rd64(locOff);
            uint64_t next = 0;

            if (pointerFormat == 1 || pointerFormat == 2) {
                const bool bind = (raw >> 63) & 1;
                next = (raw >> 51) & 0xFFF;
                if (bind) {
                    const uint32_t ordinal = raw & 0xFFFFFF;
                    if (ordinal < chImports.size()) {
                        const ChainImport& ci = chImports[ordinal];
                        std::string symName;
                        size_t symOff = static_cast<size_t>(base) + symbolsOff + ci.nameOffset;
                        if (symbolsOff != 0 && symOff < sz) {
                            symName = reinterpret_cast<const char*>(rawData_.data() + symOff);
                            size_t n = symName.find('\0');
                            if (n != std::string::npos) symName.resize(n);
                        }
                        std::string libName;
                        if (ci.libraryOrdinal > 0 &&
                            ci.libraryOrdinal <= static_cast<int32_t>(machoDylibNames_.size()))
                            libName = machoDylibNames_[ci.libraryOrdinal - 1];
                        else if (ci.libraryOrdinal == -1) libName = "(self)";
                        else if (ci.libraryOrdinal == -2) libName = "(flat)";

                        if (!symName.empty()) {
                            const uint64_t chainVm = segVmaddr + (locOff - segFileoff);
                            bool exists = false;
                            for (auto& imp : imports_) {
                                if (imp.functionName == symName && imp.address == 0) {
                                    imp.address = chainVm;
                                    if (imp.libraryName.empty()) imp.libraryName = libName;
                                    exists = true;
                                    break;
                                }
                            }
                            if (!exists) {
                                ImportInfo imp{};
                                imp.libraryName = libName;
                                imp.functionName = symName;
                                imp.address = chainVm;
                                imports_.push_back(imp);
                            }
                        }
                    }
                    // foreign symbol address unknown: null the slot
                    std::memset(rawData_.data() + locOff, 0, static_cast<size_t>(ptrSize));
                } else {
                    // rebase: target:36 | high8:8 -> pointer value
                    uint64_t value = (raw & 0xFFFFFFFFFULL) | ((raw >> 36 & 0xFF) << 56);
                    if (pointerFormat == 2) value += textAddr; // runtimeOffset
                    std::memcpy(rawData_.data() + locOff, &value, ptrSize);
                }
                return next == 0 ? 0 : locOff + next * 4;
            }

            if (pointerFormat == 7 || pointerFormat == 8 || pointerFormat == 12) {
                const bool bind = (raw >> 62) & 1;
                const bool auth = (raw >> 63) & 1;
                next = (raw >> 51) & 0x7FF;
                if (bind) {
                    const uint32_t ordinal =
                        (pointerFormat == 12) ? (raw & 0xFFFFFF) : (raw & 0xFFFF);
                    if (ordinal < chImports.size()) {
                        const ChainImport& ci = chImports[ordinal];
                        std::string symName;
                        size_t symOff = static_cast<size_t>(base) + symbolsOff + ci.nameOffset;
                        if (symbolsOff != 0 && symOff < sz) {
                            symName = reinterpret_cast<const char*>(rawData_.data() + symOff);
                            size_t n = symName.find('\0');
                            if (n != std::string::npos) symName.resize(n);
                        }
                        std::string libName;
                        if (ci.libraryOrdinal > 0 &&
                            ci.libraryOrdinal <= static_cast<int32_t>(machoDylibNames_.size()))
                            libName = machoDylibNames_[ci.libraryOrdinal - 1];
                        else if (ci.libraryOrdinal == -1) libName = "(self)";
                        else if (ci.libraryOrdinal == -2) libName = "(flat)";

                        if (!symName.empty()) {
                            const uint64_t chainVm = segVmaddr + (locOff - segFileoff);
                            bool exists = false;
                            for (auto& imp : imports_) {
                                if (imp.functionName == symName && imp.address == 0) {
                                    imp.address = chainVm;
                                    if (imp.libraryName.empty()) imp.libraryName = libName;
                                    exists = true;
                                    break;
                                }
                            }
                            if (!exists) {
                                ImportInfo imp{};
                                imp.libraryName = libName;
                                imp.functionName = symName;
                                imp.address = chainVm;
                                imports_.push_back(imp);
                            }
                        }
                    }
                    std::memset(rawData_.data() + locOff, 0, static_cast<size_t>(ptrSize));
                } else if (!auth) {
                    // rebase: 43-bit vm offset, sign extended, image-relative
                    uint64_t target = raw & 0x7FFFFFFFFFFFULL;
                    if (target & 0x40000000000ULL) target |= 0xFFFFF80000000000ULL;
                    const uint64_t value = textAddr + target;
                    std::memcpy(rawData_.data() + locOff, &value, ptrSize);
                }
                // authenticated pointers cannot be reconstructed; leave as-is
                return next == 0 ? 0 : locOff + next * 8;
            }

            return 0;
        };

        for (uint32_t s = 0; s < segCount; s++) {
            const uint32_t segInfoOff = rd32(starts + 4 + s * 4);
            if (segInfoOff == 0) continue;
            const uint32_t seg = base + segInfoOff;
            if (seg + 24 > sz) continue;
            const uint16_t pageSize = rd16(seg + 4);
            const uint16_t pointerFormat = rd16(seg + 6);
            const uint16_t pageCount = rd16(seg + 20);
            if (pageSize == 0 || pageCount == 0) continue;
            if (static_cast<uint64_t>(seg) + 24 + pageCount * 2ULL > sz) continue;
            if (pointerFormat != 1 && pointerFormat != 2 &&
                pointerFormat != 7 && pointerFormat != 8 && pointerFormat != 12)
                continue;

            // starts_in_image segment i corresponds to the i-th segment load
            // command (LLVM matches them in command order)
            uint64_t segVmaddr = imageBase_;
            uint64_t segFileoff = 0;
            if (s < machoSegments_.size()) {
                segVmaddr = machoSegments_[s].vmaddr;
                segFileoff = machoSegments_[s].fileoff;
            }

            for (uint32_t p = 0; p < pageCount; p++) {
                const uint16_t pageStart = rd16(seg + 24 + p * 2);
                if (pageStart == 0xFFFF) continue; // DYLD_CHAINED_PTR_START_NONE

                if ((pageStart & 0x8000) != 0) {
                    // DYLD_CHAINED_PTR_START_MULTI: dyld_chained_ptr_overflow
                    // records (start, count) placed after the page_start array,
                    // one record per MULTI page in page order (best-effort).
                    const uint32_t overflowBase = seg + 24 + pageCount * 2;
                    uint32_t overflowIndex = 0;
                    for (uint32_t q = 0; q < p; q++) {
                        if ((rd16(seg + 24 + q * 2) & 0x8000) != 0) overflowIndex++;
                    }
                    const uint32_t rec = overflowBase + overflowIndex * 4;
                    if (rec + 4 > sz) continue;
                    const uint16_t chainStart = rd16(rec);
                    const uint16_t chainCount = rd16(rec + 2);
                    uint64_t locOff = segFileoff + static_cast<uint64_t>(p) * pageSize + chainStart;
                    for (uint16_t c = 0; c < chainCount; c++) {
                        locOff = processChainPointer(locOff, pointerFormat, segVmaddr, segFileoff);
                        if (locOff == 0) break;
                    }
                    continue;
                }

                // single chain starting at pageStart bytes into the page
                uint64_t locOff = segFileoff + static_cast<uint64_t>(p) * pageSize + pageStart;
                for (int guard = 0; guard < 65536; guard++) {
                    locOff = processChainPointer(locOff, pointerFormat, segVmaddr, segFileoff);
                    if (locOff == 0) break;
                }
            }
        }
    }

    void parseMachOSection32(uint32_t sectionOffset, uint32_t segVMAddr) {
        SectionInfo section{};
        char nameBuf[17] = {0};
        std::memcpy(nameBuf, rawData_.data() + sectionOffset, 16);
        section.name = nameBuf;

        section.virtualAddress = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 32);
        section.virtualSize = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 36);
        section.fileOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 40);
        section.fileSize = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 44);

        uint32_t flags = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 56);
        section.isReadable = true;
        section.isWritable = (flags & 0x02000000) != 0;
        section.isExecutable = (flags & 0x80000000) != 0;
        section.reserved1 = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 60);
        section.reserved2 = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 64);

        sections_.push_back(section);
    }

    void parseMachOSection64(uint32_t sectionOffset, uint64_t segVMAddr) {
        SectionInfo section{};
        char nameBuf[17] = {0};
        std::memcpy(nameBuf, rawData_.data() + sectionOffset, 16);
        section.name = nameBuf;

        section.virtualAddress = *reinterpret_cast<uint64_t*>(rawData_.data() + sectionOffset + 32);
        section.virtualSize = *reinterpret_cast<uint64_t*>(rawData_.data() + sectionOffset + 40);
        section.fileOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 48);
        section.fileSize = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 56);

        uint32_t flags = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 64);
        section.isReadable = true;
        section.isWritable = (flags & 0x02000000) != 0;
        section.isExecutable = (flags & 0x80000000) != 0;
        section.reserved1 = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 68);
        section.reserved2 = *reinterpret_cast<uint32_t*>(rawData_.data() + sectionOffset + 72);

        sections_.push_back(section);
    }

    void parseMachONlist32(uint32_t symoff, uint32_t nsyms, uint32_t stroff, uint32_t strsize) {
        // GP-7046: a corrupt or truncated LC_SYMTAB must never allocate on
        // garbage nsyms nor read out of bounds; clamp to what the file holds.
        if (nsyms == 0) return;
        if (symoff >= rawData_.size() || rawData_.size() - symoff < 12) return;
        uint64_t tableBytes = static_cast<uint64_t>(nsyms) * 12;
        if (tableBytes > rawData_.size() - symoff)
            nsyms = static_cast<uint32_t>((rawData_.size() - symoff) / 12);
        if (nsyms == 0) return;
        machONlistNames_.resize(nsyms);
        for (uint32_t i = 0; i < nsyms; i++) {
            uint32_t entryOffset = symoff + i * 12;
            if (entryOffset + 12 > rawData_.size()) break;

            uint32_t n_strx = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset);
            uint8_t n_type = rawData_[entryOffset + 4];
            uint8_t n_sect = rawData_[entryOffset + 5];
            uint16_t n_desc = *reinterpret_cast<uint16_t*>(rawData_.data() + entryOffset + 6);
            uint32_t n_value = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset + 8);

            std::string name;
            if (stroff + n_strx < rawData_.size()) {
                name = reinterpret_cast<const char*>(rawData_.data() + stroff + n_strx);
            }
            machONlistNames_[i] = name;
            if (name.empty()) continue;

            bool isExternal = (n_type & 0x01) != 0;
            bool isDefined = (n_type & 0x0E) != 0; // N_SECT (0x0E) or N_ABS (0x02)

            if (isDefined && n_value > 0) {
                SymbolInfo sym{};
                sym.name = name;
                sym.address = n_value;
                sym.size = 0;
                sym.isFunction = true;
                sym.isExternal = isExternal;
                symbols_.push_back(sym);

                if (isExternal && n_value > 0) {
                    ExportInfo exp{};
                    exp.name = name;
                    exp.address = n_value;
                    exports_.push_back(exp);
                }
            } else if (isExternal && n_value == 0) {
                // Undefined external symbol — import reference
                // The library name comes from LC_LOAD_DYLIB commands
                ImportInfo imp{};
                imp.functionName = name;
                imp.address = 0;
                imports_.push_back(imp);
            }
        }
    }

    void parseMachONlist64(uint32_t symoff, uint32_t nsyms, uint32_t stroff, uint32_t strsize) {
        // GP-7046: same corruption guards as parseMachONlist32.
        if (nsyms == 0) return;
        if (symoff >= rawData_.size() || rawData_.size() - symoff < 16) return;
        uint64_t tableBytes = static_cast<uint64_t>(nsyms) * 16;
        if (tableBytes > rawData_.size() - symoff)
            nsyms = static_cast<uint32_t>((rawData_.size() - symoff) / 16);
        if (nsyms == 0) return;
        machONlistNames_.resize(nsyms);
        for (uint32_t i = 0; i < nsyms; i++) {
            uint32_t entryOffset = symoff + i * 16;
            if (entryOffset + 16 > rawData_.size()) break;

            uint32_t n_strx = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset);
            uint8_t n_type = rawData_[entryOffset + 4];
            uint8_t n_sect = rawData_[entryOffset + 5];
            uint16_t n_desc = *reinterpret_cast<uint16_t*>(rawData_.data() + entryOffset + 6);
            uint64_t n_value = *reinterpret_cast<uint64_t*>(rawData_.data() + entryOffset + 8);

            std::string name;
            if (stroff + n_strx < rawData_.size()) {
                name = reinterpret_cast<const char*>(rawData_.data() + stroff + n_strx);
            }
            machONlistNames_[i] = name;
            if (name.empty()) continue;

            bool isExternal = (n_type & 0x01) != 0;
            bool isDefined = (n_type & 0x0E) != 0;

            if (isDefined && n_value > 0) {
                SymbolInfo sym{};
                sym.name = name;
                sym.address = n_value;
                sym.size = 0;
                sym.isFunction = true;
                sym.isExternal = isExternal;
                symbols_.push_back(sym);

                if (isExternal && n_value > 0) {
                    ExportInfo exp{};
                    exp.name = name;
                    exp.address = n_value;
                    exports_.push_back(exp);
                }
            } else if (isExternal && n_value == 0) {
                ImportInfo imp{};
                imp.functionName = name;
                imp.address = 0;
                imports_.push_back(imp);
            }
        }
    }

    // Task 2.4 / GP-7088: COFF object files (.obj) and COFF archives (.lib) are
    // unlinked: section VirtualAddress fields are 0, so sections are laid out
    // cumulatively at 0x1000 alignment from image base 0 (mirrors Ghidra's
    // CoffLoader), relocations are patched into the raw bytes so disassembly
    // sees resolved addresses, and undefined externals surface as imports.
    bool parseCOFF() {
        if (rawData_.size() < 20) return false;
        return parseCOFFBytes(0, rawData_.size(), 0, "");
    }

    bool parseCOFFArchive() {
        // ar archive: "!<arch>\n" then 60-byte member headers; members are
        // 2-byte aligned (odd sizes padded with '\n'). "/" (symbol table) and
        // "//" (long name table) members are skipped; each COFF member is
        // parsed into the same sections/symbols/imports with its own VA block.
        formatName_ = "COFF Archive";
        uint64_t pos = 8;
        uint64_t nextVa = 0;
        bool any = false;
        while (pos + 60 <= rawData_.size()) {
            char nameBuf[17] = {};
            std::memcpy(nameBuf, rawData_.data() + pos, 16);
            std::string name(nameBuf);
            size_t slash = name.find('/');
            if (slash != std::string::npos) name = name.substr(0, slash);
            while (!name.empty() && name.back() == ' ') name.pop_back();

            char sizeBuf[11] = {};
            std::memcpy(sizeBuf, rawData_.data() + pos + 48, 10);
            uint64_t memberSize = static_cast<uint64_t>(std::strtoul(sizeBuf, nullptr, 10));
            uint64_t dataOff = pos + 60;
            if (dataOff + memberSize > rawData_.size()) break;

            if (!name.empty() && name != "/" && name != "//" && memberSize >= 20 + 40 &&
                isCoffMachine(coff16(dataOff)) && coff16(dataOff + 2) > 0 &&
                coff16(dataOff + 16) == 0) {
                any = parseCOFFBytes(dataOff, memberSize, nextVa, name) || any;
                uint64_t memberEnd = 0;
                for (const auto& s : sections_) {
                    memberEnd = std::max(memberEnd,
                                         s.virtualAddress + std::max(s.virtualSize, s.fileSize));
                }
                nextVa = (memberEnd + 0xFFF) & ~0xFFFULL;
            }

            pos = dataOff + memberSize;
            if (pos & 1) ++pos;
        }
        return any;
    }

    // Intel HEX format parser
    // Records: :LLAAAATT[DD...]CC
    // LL=byte count, AAAA=address, TT=type, DD=data, CC=checksum
    bool parseIntelHex() {
        formatName_ = "Intel HEX";
        arch_ = "unknown";
        bitness_ = 32;

        std::string content(rawData_.begin(), rawData_.end());
        std::istringstream stream(content);
        std::string line;
        uint32_t baseAddr = 0;
        uint32_t minAddr = 0xFFFFFFFF;
        uint32_t maxAddr = 0;
        std::vector<uint8_t> data;

        while (std::getline(stream, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty() || line[0] != ':') continue;
            if (line.size() < 11) continue;

            auto hexByte = [](const std::string& s, int pos) -> uint8_t {
                return static_cast<uint8_t>(
                    (std::stoi(s.substr(pos, 1), nullptr, 16) << 4) |
                    std::stoi(s.substr(pos + 1, 1), nullptr, 16));
            };

            uint8_t byteCount = hexByte(line, 1);
            uint16_t address = static_cast<uint16_t>(
                (hexByte(line, 3) << 8) | hexByte(line, 5));
            uint8_t recordType = hexByte(line, 7);

            uint8_t checksum = 0;
            for (size_t i = 1; i + 1 < line.size(); i += 2) {
                checksum += hexByte(line, static_cast<int>(i));
            }
            if (checksum != 0) continue;

            switch (recordType) {
                case 0x00: {
                    uint32_t addr = baseAddr + address;
                    for (uint8_t i = 0; i < byteCount; ++i) {
                        uint8_t val = hexByte(line, 9 + i * 2);
                        uint32_t targetAddr = addr + i;
                        if (targetAddr >= data.size()) data.resize(targetAddr + 1, 0);
                        data[targetAddr] = val;
                        minAddr = std::min(minAddr, targetAddr);
                        maxAddr = std::max(maxAddr, targetAddr);
                    }
                    break;
                }
                case 0x01: break;
                case 0x02: baseAddr = static_cast<uint32_t>((hexByte(line, 9) << 8) | hexByte(line, 11)) << 4; break;
                case 0x04: baseAddr = static_cast<uint32_t>((hexByte(line, 9) << 8) | hexByte(line, 11)) << 16; break;
                default: break;
            }
        }

        if (data.empty() || minAddr > maxAddr) return false;

        uint64_t size = maxAddr - minAddr + 1;
        SectionInfo sec{};
        sec.name = ".text";
        sec.virtualAddress = minAddr;
        sec.virtualSize = size;
        sec.fileOffset = 0;
        sec.fileSize = size;
        sec.isReadable = true;
        sec.isExecutable = true;
        sections_.push_back(sec);

        rawData_ = data;
        entryPoint_ = minAddr;
        return true;
    }

    // Motorola S-Record format parser
    bool parseSRecord() {
        formatName_ = "Motorola S-Record";
        arch_ = "unknown";
        bitness_ = 32;

        std::string content(rawData_.begin(), rawData_.end());
        std::istringstream stream(content);
        std::string line;
        uint32_t minAddr = 0xFFFFFFFF;
        uint32_t maxAddr = 0;
        std::vector<uint8_t> data;

        while (std::getline(stream, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty() || line[0] != 'S') continue;
            if (line.size() < 4) continue;

            auto hexByte = [](const std::string& s, int pos) -> uint8_t {
                return static_cast<uint8_t>(
                    (std::stoi(s.substr(pos, 1), nullptr, 16) << 4) |
                    std::stoi(s.substr(pos + 1, 1), nullptr, 16));
            };

            char recordType = line[1];
            uint8_t byteCount = hexByte(line, 2);

            uint8_t checksum = 0;
            for (size_t i = 2; i + 1 < line.size(); i += 2) {
                checksum += hexByte(line, static_cast<int>(i));
            }
            if ((checksum & 0xFF) != 0xFF) continue;

            int addrSize = 0;
            switch (recordType) {
                case '0': case '5': case '9': addrSize = 2; break;
                case '1': case '8': addrSize = 2; break;
                case '2': case '6': addrSize = 3; break;
                case '3': case '7': addrSize = 4; break;
                default: continue;
            }

            uint32_t address = 0;
            for (int i = 0; i < addrSize; ++i) {
                address = (address << 8) | hexByte(line, 4 + i * 2);
            }

            int dataStart = 4 + addrSize * 2;
            int dataBytes = byteCount - addrSize - 1;

            if (recordType == '1' || recordType == '2' || recordType == '3') {
                for (int i = 0; i < dataBytes; ++i) {
                    uint8_t val = hexByte(line, dataStart + i * 2);
                    uint32_t targetAddr = address + i;
                    if (targetAddr >= data.size()) data.resize(targetAddr + 1, 0);
                    data[targetAddr] = val;
                    minAddr = std::min(minAddr, targetAddr);
                    maxAddr = std::max(maxAddr, targetAddr);
                }
            } else if (recordType == '7' || recordType == '8' || recordType == '9') {
                entryPoint_ = address;
            }
        }

        if (data.empty() || minAddr > maxAddr) return false;

        uint64_t size = maxAddr - minAddr + 1;
        SectionInfo sec{};
        sec.name = ".text";
        sec.virtualAddress = minAddr;
        sec.virtualSize = size;
        sec.fileOffset = 0;
        sec.fileSize = size;
        sec.isReadable = true;
        sec.isExecutable = true;
        sections_.push_back(sec);

        rawData_ = data;
        if (entryPoint_ == 0) entryPoint_ = minAddr;
        return true;
    }

    bool parseCOFFBytes(uint64_t base, uint64_t size, uint64_t baseVa,
                        const std::string& memberTag) {
        uint16_t machine = coff16(base);
        uint16_t numSecs = coff16(base + 2);
        uint32_t symTabOff = coff32(base + 8);
        uint32_t numSyms = coff32(base + 12);
        uint16_t optSize = coff16(base + 16);
        if (size < 20 + static_cast<uint64_t>(numSecs) * 40 || numSecs == 0 || optSize != 0) {
            return false;
        }
        if (formatName_.empty() || formatName_ == "COFF" || formatName_ == "COFF Archive") {
            switch (machine) {
                case 0x8664: arch_ = "x86"; bitness_ = 64; break;
                case 0xAA64: arch_ = "AARCH64"; bitness_ = 64; break;
                case 0x14C: arch_ = "x86"; bitness_ = 32; break;
                case 0x1C0: case 0x1C4: case 0x1C2: arch_ = "ARM"; bitness_ = 32; break;
                default: return false;
            }
            if (formatName_.empty()) formatName_ = "COFF";
        }

        uint64_t strTabOff = symTabOff + static_cast<uint64_t>(numSyms) * 18;
        auto strAt = [&](uint64_t off) -> std::string {
            if (off >= size) return "";
            const char* p = reinterpret_cast<const char*>(rawData_.data() + base + off);
            size_t len = 0;
            while (len < size - off && p[len] != '\0') ++len;
            return std::string(p, len);
        };
        auto secName = [&](uint64_t so) -> std::string {
            char buf[9] = {};
            std::memcpy(buf, rawData_.data() + so, 8);
            if (buf[0] == '/') {
                char* end = nullptr;
                long off = std::strtol(buf + 1, &end, 10);
                if (end != buf + 1 && off > 0) return strAt(static_cast<uint64_t>(off));
            }
            return std::string(buf);
        };
        auto symName = [&](uint64_t so) -> std::string {
            uint32_t inlineOff = coff32(base + so + 4);
            if (coff32(base + so) == 0 && inlineOff != 0) return strAt(inlineOff);
            char buf[9] = {};
            std::memcpy(buf, rawData_.data() + base + so, 8);
            if (buf[0] == '/') {
                char* end = nullptr;
                long off = std::strtol(buf + 1, &end, 10);
                if (end != buf + 1 && off > 0) return strAt(static_cast<uint64_t>(off));
            }
            return std::string(buf);
        };

        // Sections: cumulative 0x1000-aligned layout from baseVa.
        struct CoffSection {
            std::string name;
            uint64_t va = 0;
            uint64_t rawOff = 0;
            uint64_t rawSize = 0;
            uint32_t relocOff = 0;
            uint32_t numRelocs = 0;
        };
        std::vector<CoffSection> coffSecs;
        coffSecs.reserve(numSecs);
        uint64_t nextVa = baseVa;
        uint64_t secHdr = base + 20 + optSize;
        for (uint16_t i = 0; i < numSecs; ++i) {
            uint64_t so = secHdr + static_cast<uint64_t>(i) * 40;
            CoffSection cs{};
            cs.name = secName(so);
            cs.rawOff = coff32(so + 20);
            cs.rawSize = coff32(so + 16);
            uint32_t virtSize = coff32(so + 8);
            cs.relocOff = coff32(so + 24);
            cs.numRelocs = coff16(so + 32);
            uint32_t chars = coff32(so + 36);
            cs.va = nextVa;

            SectionInfo sec{};
            sec.name = memberTag.empty() ? cs.name : memberTag + "_" + cs.name;
            sec.virtualAddress = cs.va;
            sec.fileOffset = base + cs.rawOff;
            sec.fileSize = cs.rawSize;
            sec.virtualSize = std::max<uint64_t>(virtSize, cs.rawSize);
            sec.isReadable = true;
            sec.isWritable = (chars & 0x80000000u) != 0;
            sec.isExecutable = (chars & 0x20u) != 0;
            sections_.push_back(sec);

            uint64_t span = std::max<uint64_t>(sec.virtualSize, 1);
            nextVa = (cs.va + span + 0xFFF) & ~0xFFFULL;
            coffSecs.push_back(cs);
        }

        // Symbols (skip auxiliaries; section/file records have no real address).
        struct CoffSymbol {
            std::string name;
            uint64_t value = 0;
            int16_t secNum = 0;
            uint16_t type = 0;
            uint8_t storageClass = 0;
        };
        std::vector<CoffSymbol> syms;
        std::vector<int> symAtPos;
        for (uint32_t i = 0; i < numSyms;) {
            uint64_t so = symTabOff + static_cast<uint64_t>(i) * 18;
            uint8_t numAux = (so + 18 <= size) ? rawData_[base + so + 17] : 0;
            symAtPos.push_back(static_cast<int>(syms.size()));
            CoffSymbol s{};
            s.name = symName(so);
            s.value = coff32(base + so + 8);
            s.secNum = static_cast<int16_t>(coff16(base + so + 12));
            s.type = coff16(base + so + 14);
            s.storageClass = rawData_[base + so + 16];
            syms.push_back(s);
            i += 1 + numAux;
            for (uint8_t a = 0; a < numAux; ++a) symAtPos.push_back(-1);
        }

        for (const auto& s : syms) {
            if (s.name.empty() || s.storageClass == 3) continue;
            if (s.secNum > 0 && static_cast<size_t>(s.secNum) <= coffSecs.size()) {
                SymbolInfo sym{};
                sym.name = s.name;
                sym.address = coffSecs[s.secNum - 1].va + s.value;
                sym.isFunction = (s.type == 0x20);
                sym.isExternal = (s.storageClass == 2);
                symbols_.push_back(sym);
                if (sym.isFunction &&
                    (s.name == "main" || s.name == "_main" || s.name == "WinMain" ||
                     s.name == "wmain" || s.name == "_WinMain")) {
                    entryPoint_ = sym.address;
                }
            } else if (s.secNum == -1) {
                SymbolInfo sym{};
                sym.name = s.name;
                sym.address = s.value;
                sym.isFunction = (s.type == 0x20);
                sym.isExternal = (s.storageClass == 2);
                symbols_.push_back(sym);
            } else if (s.secNum == 0 && s.storageClass == 2) {
                ImportInfo imp{};
                imp.libraryName = "(coff)";
                imp.functionName = s.name;
                imp.address = 0;
                imports_.push_back(imp);
            }
        }

        // Relocations: patch the supported types into the raw bytes.
        auto put32 = [&](uint64_t off, uint32_t v) {
            for (int b = 0; b < 4; ++b) rawData_[off + b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFF);
        };
        auto put64 = [&](uint64_t off, uint64_t v) {
            for (int b = 0; b < 8; ++b) rawData_[off + b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFF);
        };
        for (const auto& cs : coffSecs) {
            if (cs.numRelocs == 0 || cs.relocOff == 0) continue;
            for (uint32_t j = 0; j < cs.numRelocs; ++j) {
                uint64_t r = cs.relocOff + static_cast<uint64_t>(j) * 10;
                if (r + 10 > size) break;
                uint32_t relVa = coff32(base + r);
                uint32_t symIdx = coff32(base + r + 4);
                uint16_t rtype = coff16(base + r + 8);
                if (symIdx >= symAtPos.size()) continue;
                int realIdx = symAtPos[symIdx];
                if (realIdx < 0 || static_cast<size_t>(realIdx) >= syms.size()) continue;
                const CoffSymbol& s = syms[realIdx];
                uint64_t target = 0;
                bool resolved = false;
                if (s.secNum > 0 && static_cast<size_t>(s.secNum) <= coffSecs.size()) {
                    target = coffSecs[s.secNum - 1].va + s.value;
                    resolved = true;
                } else if (s.secNum == -1) {
                    target = s.value;
                    resolved = true;
                }
                uint64_t patchOff = base + cs.rawOff + relVa;
                uint64_t insAddr = cs.va + relVa;
                switch (rtype) {
                    case 0x0001:  // AMD64 ADDR64
                    case 0x000E:  // ARM64 ADDR64
                        if (resolved && patchOff + 8 <= rawData_.size()) put64(patchOff, target);
                        break;
                    case 0x0002:  // ARM64 ADDR32
                        if (resolved && patchOff + 4 <= rawData_.size()) put32(patchOff, static_cast<uint32_t>(target));
                        break;
                    case 0x0003: {  // ARM64 BRANCH26
                        if (!resolved || patchOff + 4 > rawData_.size()) break;
                        uint32_t u = coff32(patchOff);
                        int32_t imm = static_cast<int32_t>(u & 0x03FFFFFFu);
                        if (imm & 0x02000000) imm |= static_cast<int32_t>(~0x03FFFFFF);
                        int64_t newImm = (static_cast<int64_t>(target) - static_cast<int64_t>(insAddr)) >> 2;
                        put32(patchOff, (u & ~0x03FFFFFFu) |
                                        (static_cast<uint32_t>(newImm) & 0x03FFFFFFu));
                        break;
                    }
                    case 0x0004: {  // AMD64 REL32
                        if (!resolved || patchOff + 4 > rawData_.size()) break;
                        int64_t newDisp = static_cast<int64_t>(target) - static_cast<int64_t>(insAddr + 4);
                        put32(patchOff, static_cast<uint32_t>(newDisp));
                        break;
                    }
                    default:
                        break;
                }
            }
        }

        return true;
    }

    uint64_t rvaToFileOffset(uint64_t rva) const {
        if (rva == 0) {
            return INVALID_FILE_OFFSET;
        }

        uint64_t normalizedRva = rva;
        if (formatName_ == "PE" && imageBase_ != 0 && rva >= imageBase_) {
            normalizedRva = rva - imageBase_;
        }

        for (const auto& section : sections_) {
            uint64_t sectionRva = section.virtualAddress;
            if (formatName_ == "PE" && imageBase_ != 0 && section.virtualAddress >= imageBase_) {
                sectionRva = section.virtualAddress - imageBase_;
            }

            uint64_t span = getSectionSpan(section);
            if (span == 0 || normalizedRva < sectionRva) {
                continue;
            }

            uint64_t withinSection = normalizedRva - sectionRva;
            if (withinSection < span) {
                if (withinSection >= section.fileSize) {
                    return INVALID_FILE_OFFSET;
                }
                return section.fileOffset + withinSection;
            }
        }

        if (normalizedRva < rawData_.size()) {
            return normalizedRva;
        }

        return INVALID_FILE_OFFSET;
    }

    std::string readStringAtRVA(uint64_t rva) const {
        uint64_t offset = rvaToFileOffset(rva);
        if (!isValidFileOffset(offset)) return "";

        const char* str = reinterpret_cast<const char*>(rawData_.data() + offset);
        size_t maxLen = rawData_.size() - offset;
        size_t len = 0;
        while (len < maxLen && str[len] != '\0') len++;

        return std::string(str, len);
    }

    std::string formatName_;
    std::string arch_;
    int bitness_ = 32;
    bool elfBigEndian_ = false;
    uint32_t cpusubtype_ = 0;
    uint32_t dysymtabIndirectSymOffset_ = 0;
    uint32_t dysymtabIndirectSymCount_ = 0;
    std::vector<std::string> machONlistNames_;
    std::vector<std::string> machoDylibNames_;
    struct MachOSegInfo {
        std::string name;
        uint64_t vmaddr;
        uint64_t fileoff;
    };
    std::vector<MachOSegInfo> machoSegments_;
    uint64_t machoTextAddr_ = 0;
    uint32_t chainedFixupsOff_ = 0;
    uint32_t chainedFixupsSize_ = 0;
    std::vector<DyldCacheImageInfo> dyldCacheImages_;
    bool isDyldCache_ = false;
    uint64_t entryPoint_ = 0;
    uint64_t imageBase_ = 0;
    size_t fileSize_ = 0;
    std::vector<uint8_t> rawData_;
    std::vector<SectionInfo> sections_;
    std::vector<ElfPhdr> phdrs_;
    std::vector<SymbolInfo> symbols_;
    std::vector<ImportInfo> imports_;
    std::vector<ExportInfo> exports_;
    std::vector<RelocationInfo> relocations_;
};

std::unique_ptr<BinaryLoader> createLoader() {
    return std::make_unique<SimplePELoader>();
}

} // namespace ghidra
