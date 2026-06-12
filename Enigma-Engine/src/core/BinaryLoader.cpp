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

namespace ghidra {

MemoryBlockType BinaryLoader::sectionToMemoryBlockType(const SectionInfo& section) {
    if (section.isExecutable) return MemoryBlockType::DEFAULT;
    return MemoryBlockType::DEFAULT;
}

std::string BinaryLoader::guessLanguageFromArch(const std::string& arch, int bitness) {
    if (arch.find("x86") != std::string::npos || arch.find("i386") != std::string::npos ||
        arch.find("i686") != std::string::npos) {
        return bitness == 64 ? "x86:LE:64:default" : "x86:LE:32:default";
    }
    if (arch.find("ARM") != std::string::npos || arch.find("arm") != std::string::npos) {
        return bitness == 64 ? "AARCH64:LE:64:default" : "ARM:LE:32:v8";
    }
    if (arch.find("MIPS") != std::string::npos || arch.find("mips") != std::string::npos) {
        return bitness == 64 ? "MIPS:BE:64:default" : "MIPS:BE:32:default";
    }
    if (arch.find("PowerPC") != std::string::npos || arch.find("ppc") != std::string::npos) {
        return bitness == 64 ? "PowerPC:BE:64:default" : "PowerPC:BE:32:default";
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
        return false;
    }
    uint64_t getEntryPoint() const override { return entryPoint_; }
    uint64_t getImageBase() const override { return imageBase_; }

    std::vector<SectionInfo> getSections() const override { return sections_; }
    std::vector<SymbolInfo> getSymbols() const override { return symbols_; }
    std::vector<ImportInfo> getImports() const override { return imports_; }
    std::vector<ExportInfo> getExports() const override { return exports_; }
    std::vector<RelocationInfo> getRelocations() const override { return relocations_; }

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

        std::string languageId = guessLanguageFromArch(arch_, bitness_);
        if (!languageId.empty() && languageId != "unknown") {
            program->setLanguageID(LanguageID(languageId));
        }
        program->setCompilerSpecID(CompilerSpecID(guessCompilerSpecFromArch(arch_, bitness_)));

        AddressSpace* ramSpace = nullptr;
        for (const auto* space : addrFactory->getAddressSpaces()) {
            if (space->isMemorySpace()) {
                ramSpace = const_cast<AddressSpace*>(space);
                break;
            }
        }
        if (!ramSpace) return false;

        for (const auto& section : sections_) {
            Address startAddr(ramSpace, static_cast<int64_t>(section.virtualAddress));
            std::vector<uint8_t> bytes = getBytes(section.virtualAddress, section.virtualSize);
            if (bytes.empty() && section.fileSize > 0 && section.fileOffset + section.fileSize <= rawData_.size()) {
                bytes.assign(rawData_.begin() + static_cast<size_t>(section.fileOffset),
                             rawData_.begin() + static_cast<size_t>(section.fileOffset + section.fileSize));
            }

            DefaultMemoryBlock* block = nullptr;
            if (!bytes.empty()) {
                block = mem->createInitializedBlock(section.name, startAddr,
                    static_cast<long long>(bytes.size()), false);
                if (block) {
                    mem->setBytes(startAddr, bytes.data(), static_cast<int>(bytes.size()));
                }
            } else {
                block = mem->createUninitializedBlock(section.name, startAddr,
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
                    uint64_t sectionEnd = entrySection->virtualAddress + span - 1;
                    bodyEnd = std::min(sectionEnd, entryPoint_ + 63);
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

    bool parseELF() {
        formatName_ = "ELF";
        bitness_ = (rawData_[4] == 2) ? 64 : 32;

        uint16_t machine = *reinterpret_cast<uint16_t*>(rawData_.data() + 18);
        switch (machine) {
            case 0x03: arch_ = "x86"; bitness_ = 32; break;
            case 0x3E: arch_ = "x86"; bitness_ = 64; break;
            case 0x28: arch_ = "ARM"; bitness_ = 32; break;
            case 0xB7: arch_ = "AARCH64"; bitness_ = 64; break;
            case 0x08: arch_ = "MIPS"; bitness_ = 32; break;
            case 0xF3: arch_ = "RISCV"; bitness_ = 64; break;
            default: arch_ = "unknown"; break;
        }

        if (bitness_ == 32) {
            entryPoint_ = *reinterpret_cast<uint32_t*>(rawData_.data() + 24);
        } else {
            entryPoint_ = *reinterpret_cast<uint64_t*>(rawData_.data() + 24);
        }

        imageBase_ = 0;

        if (bitness_ == 32) {
            parseELF32();
        } else {
            parseELF64();
        }

        parseELFSymbols();
        parseELFImports();

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
            if (optHeaderOffset + 120 > rawData_.size()) return;
            exportDirRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 112);
        } else {
            if (optHeaderOffset + 136 > rawData_.size()) return;
            exportDirRVA = *reinterpret_cast<uint32_t*>(rawData_.data() + optHeaderOffset + 128);
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
        uint32_t shoff = *reinterpret_cast<uint32_t*>(rawData_.data() + 32);
        uint16_t shnum = *reinterpret_cast<uint16_t*>(rawData_.data() + 48);
        uint16_t shentsize = *reinterpret_cast<uint16_t*>(rawData_.data() + 46);
        uint16_t shstrndx = *reinterpret_cast<uint16_t*>(rawData_.data() + 50);

        std::vector<uint32_t> sectionNames(shnum);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;

            SectionInfo section{};
            uint32_t nameIdx = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset);
            section.type = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 4);
            section.virtualAddress = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 12);
            section.fileOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 16);
            section.fileSize = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 20);
            section.virtualSize = section.fileSize;

            uint32_t flags = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 8);
            section.isReadable = (flags & 0x2) != 0;
            section.isWritable = (flags & 0x1) != 0;
            section.isExecutable = (flags & 0x4) != 0;

            sectionNames[i] = nameIdx;
            sections_.push_back(section);
        }

        if (shstrndx < shnum) {
            uint32_t strSecOffset = shoff + shstrndx * shentsize;
            uint32_t strOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + strSecOffset + 16);

            for (size_t i = 0; i < sections_.size(); i++) {
                uint32_t nameOff = strOffset + sectionNames[i];
                if (nameOff < rawData_.size()) {
                    sections_[i].name = reinterpret_cast<const char*>(rawData_.data() + nameOff);
                }
            }
        }
    }

    void parseELF64() {
        uint64_t shoff = *reinterpret_cast<uint64_t*>(rawData_.data() + 40);
        uint16_t shnum = *reinterpret_cast<uint16_t*>(rawData_.data() + 60);
        uint16_t shentsize = *reinterpret_cast<uint16_t*>(rawData_.data() + 58);
        uint16_t shstrndx = *reinterpret_cast<uint16_t*>(rawData_.data() + 62);

        std::vector<uint32_t> sectionNames(shnum);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;

            SectionInfo section{};
            uint32_t nameIdx = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset);
            section.type = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 4);
            section.virtualAddress = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 16);
            section.fileOffset = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 24);
            section.fileSize = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 32);
            section.virtualSize = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 40);

            uint64_t flags = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 8);
            section.isReadable = (flags & 0x2) != 0;
            section.isWritable = (flags & 0x1) != 0;
            section.isExecutable = (flags & 0x4) != 0;

            sectionNames[i] = nameIdx;
            sections_.push_back(section);
        }

        if (shstrndx < shnum) {
            uint64_t strSecOffset = shoff + shstrndx * shentsize;
            uint64_t strOffset = *reinterpret_cast<uint64_t*>(rawData_.data() + strSecOffset + 24);

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
        uint32_t shoff = *reinterpret_cast<uint32_t*>(rawData_.data() + 32);
        uint16_t shnum = *reinterpret_cast<uint16_t*>(rawData_.data() + 48);
        uint16_t shentsize = *reinterpret_cast<uint16_t*>(rawData_.data() + 46);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;

            uint32_t type = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 4);
            if (type != 2 && type != 11) continue;

            uint32_t symOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 16);
            uint32_t symSize = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 20);
            uint32_t linkIdx = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 24);
            uint32_t entSize = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 36);
            if (entSize == 0) entSize = 16;

            uint32_t strTabOffset = 0;
            if (linkIdx < shnum) {
                uint32_t linkOffset = shoff + linkIdx * shentsize;
                strTabOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + linkOffset + 16);
            }

            uint32_t numSymbols = symSize / entSize;
            for (uint32_t j = 0; j < numSymbols; j++) {
                uint32_t symOff = symOffset + j * entSize;
                if (symOff + 16 > rawData_.size()) break;

                uint32_t nameIdx = *reinterpret_cast<uint32_t*>(rawData_.data() + symOff);
                uint32_t value = *reinterpret_cast<uint32_t*>(rawData_.data() + symOff + 4);
                uint32_t size = *reinterpret_cast<uint32_t*>(rawData_.data() + symOff + 8);
                uint8_t info = rawData_[symOff + 12];
                uint8_t bind = info >> 4;
                uint8_t stype = info & 0xF;

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
                sym.isExternal = (bind == 1);
                symbols_.push_back(sym);
            }
        }
    }

    void parseELF64Symbols() {
        uint64_t shoff = *reinterpret_cast<uint64_t*>(rawData_.data() + 40);
        uint16_t shnum = *reinterpret_cast<uint16_t*>(rawData_.data() + 60);
        uint16_t shentsize = *reinterpret_cast<uint16_t*>(rawData_.data() + 58);

        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;

            uint32_t type = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 4);
            if (type != 2 && type != 11) continue;

            uint64_t symOffset = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 24);
            uint64_t symSize = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 32);
            uint32_t linkIdx = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 24);
            uint64_t entSize = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 56);
            if (entSize == 0) entSize = 24;

            uint64_t strTabOffset = 0;
            if (linkIdx < shnum) {
                uint64_t linkOffset = shoff + linkIdx * shentsize;
                strTabOffset = *reinterpret_cast<uint64_t*>(rawData_.data() + linkOffset + 24);
            }

            uint64_t numSymbols = symSize / entSize;
            for (uint64_t j = 0; j < numSymbols; j++) {
                uint64_t symOff = symOffset + j * entSize;
                if (symOff + 24 > rawData_.size()) break;

                uint32_t nameIdx = *reinterpret_cast<uint32_t*>(rawData_.data() + symOff);
                uint8_t info = rawData_[symOff + 4];
                uint8_t bind = info >> 4;
                uint8_t stype = info & 0xF;
                uint64_t value = *reinterpret_cast<uint64_t*>(rawData_.data() + symOff + 8);
                uint64_t size = *reinterpret_cast<uint64_t*>(rawData_.data() + symOff + 16);

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
                sym.isExternal = (bind == 1);
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
        uint32_t shoff = *reinterpret_cast<uint32_t*>(rawData_.data() + 32);
        uint16_t shnum = *reinterpret_cast<uint16_t*>(rawData_.data() + 48);
        uint16_t shentsize = *reinterpret_cast<uint16_t*>(rawData_.data() + 46);

        uint32_t dynOffset = 0, dynSize = 0, strTabOffset = 0;
        for (uint16_t i = 0; i < shnum; ++i) {
            uint32_t secOffset = shoff + i * shentsize;
            if (secOffset + 40 > rawData_.size()) break;
            uint32_t type = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 4);
            if (type == 6) {
                dynOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 16);
                dynSize = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 20);
            }
            if (type == 3) {
                strTabOffset = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 16);
            }
        }

        if (dynOffset == 0) return;

        uint32_t numEntries = dynSize / 8;
        for (uint32_t i = 0; i < numEntries; i++) {
            uint32_t entryOffset = dynOffset + i * 8;
            if (entryOffset + 8 > rawData_.size()) break;

            int32_t tag = *reinterpret_cast<int32_t*>(rawData_.data() + entryOffset);
            uint32_t val = *reinterpret_cast<uint32_t*>(rawData_.data() + entryOffset + 4);

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
        uint64_t shoff = *reinterpret_cast<uint64_t*>(rawData_.data() + 40);
        uint16_t shnum = *reinterpret_cast<uint16_t*>(rawData_.data() + 60);
        uint16_t shentsize = *reinterpret_cast<uint16_t*>(rawData_.data() + 58);

        uint64_t dynOffset = 0, dynSize = 0, strTabOffset = 0;
        for (uint16_t i = 0; i < shnum; ++i) {
            uint64_t secOffset = shoff + i * shentsize;
            if (secOffset + 64 > rawData_.size()) break;
            uint32_t type = *reinterpret_cast<uint32_t*>(rawData_.data() + secOffset + 4);
            if (type == 6) {
                dynOffset = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 24);
                dynSize = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 32);
            }
            if (type == 3) {
                strTabOffset = *reinterpret_cast<uint64_t*>(rawData_.data() + secOffset + 24);
            }
        }

        if (dynOffset == 0) return;

        uint64_t numEntries = dynSize / 16;
        for (uint64_t i = 0; i < numEntries; i++) {
            uint64_t entryOffset = dynOffset + i * 16;
            if (entryOffset + 16 > rawData_.size()) break;

            int64_t tag = *reinterpret_cast<int64_t*>(rawData_.data() + entryOffset);
            uint64_t val = *reinterpret_cast<uint64_t*>(rawData_.data() + entryOffset + 8);

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
