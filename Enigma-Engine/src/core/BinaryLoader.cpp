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

        for (const auto& imp : imports_) {
            if (imp.address > 0) {
                Address impAddr(ramSpace, static_cast<int64_t>(imp.address));
                symTable->createLabel(impAddr, imp.functionName, SourceType::IMPORTED);
            }
        }

        for (const auto& exp : exports_) {
            if (exp.address > 0) {
                Address expAddr(ramSpace, static_cast<int64_t>(exp.address));
                symTable->createLabel(expAddr, exp.name, SourceType::IMPORTED);
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
        if (bitness_ == 32) {
            if (optHeaderOffset + 104 > rawData_.size()) return;
            exportDirRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 96);
        } else {
            if (optHeaderOffset + 120 > rawData_.size()) return;
            exportDirRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 112);
        }

        if (exportDirRVA == 0) return;

        uint64_t exportOffset = rvaToFileOffset(exportDirRVA);
        if (!isValidFileOffset(exportOffset) || exportOffset + 40 > rawData_.size()) return;

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
            if (!name.empty()) {
                ExportInfo exp{};
                exp.name = name;
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
            }
            cmdOffset += cmdsize;
        }

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
            }
            cmdOffset += cmdsize;
        }

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

        // Read indirect symbol table
        const uint32_t* indirectTable = reinterpret_cast<const uint32_t*>(
            rawData_.data() + dysymtabIndirectSymOffset_);
        uint32_t tableCount = dysymtabIndirectSymCount_;

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
    uint64_t entryPoint_ = 0;
    uint64_t imageBase_ = 0;
    size_t fileSize_ = 0;
    std::vector<uint8_t> rawData_;
    std::vector<SectionInfo> sections_;
    std::vector<SymbolInfo> symbols_;
    std::vector<ImportInfo> imports_;
    std::vector<ExportInfo> exports_;
    std::vector<RelocationInfo> relocations_;
};

std::unique_ptr<BinaryLoader> createLoader() {
    return std::make_unique<SimplePELoader>();
}

} // namespace ghidra
