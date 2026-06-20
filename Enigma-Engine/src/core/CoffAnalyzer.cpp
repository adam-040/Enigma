#include <ghidra/CoffAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <algorithm>

namespace ghidra {

CoffAnalyzer::CoffAnalyzer()
    : AbstractBinaryFormatAnalyzer("COFF Header",
                                   "Analyzes COFF object file headers and sections.") {
}

bool CoffAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Common Object File Format (COFF)";
}

static uint16_t readU16(const uint8_t* buf, bool le) {
    return le
        ? (static_cast<uint16_t>(buf[1]) << 8) | buf[0]
        : (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
}

static uint32_t readU32(const uint8_t* buf, bool le) {
    return le
        ? (static_cast<uint32_t>(buf[3]) << 24) | (static_cast<uint32_t>(buf[2]) << 16) |
          (static_cast<uint32_t>(buf[1]) << 8) | buf[0]
        : (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) |
          (static_cast<uint32_t>(buf[2]) << 8) | buf[3];
}

bool CoffAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing COFF header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[2] = {0};
    if (memory->getBytes(addr, magic, 2) != 2) return false;
    bool isValid = (magic[0] == 0x4C && magic[1] == 0x01) ||
                   (magic[0] == 0x64 && magic[1] == 0x86) ||
                   (magic[0] == 0x4C && magic[1] == 0x02);
    if (!isValid) return false;

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!dtm || !listing || !symTable) return false;

    // COFF is little-endian
    bool le = true;

    StructureDataType* coffHeader = new StructureDataType("COFF_File_Header", 0, dtm);
    coffHeader->add(&WordDataType::dataType(), 2, "f_magic", "");
    coffHeader->add(&WordDataType::dataType(), 2, "f_nscns", "");
    coffHeader->add(&DWordDataType::dataType(), 4, "f_timdat", "");
    coffHeader->add(&DWordDataType::dataType(), 4, "f_symptr", "");
    coffHeader->add(&DWordDataType::dataType(), 4, "f_nsyms", "");
    coffHeader->add(&WordDataType::dataType(), 2, "f_opthdr", "");
    coffHeader->add(&WordDataType::dataType(), 2, "f_flags", "");

    DataType* resolvedHeader = dtm->resolve(coffHeader, nullptr);
    if (!resolvedHeader) return false;

    Data* headerData = listing->createData(addr, resolvedHeader);
    if (headerData) headerData->setComment("COFF File Header");
    symTable->createLabel(addr, "COFF_HEADER", SourceType::ANALYSIS);

    // Read section count and optional header size
    uint8_t buf[4] = {0};
    if (memory->getBytes(addr.add(2), buf, 2) != 2) {
        if (monitor) monitor->setMessage("COFF analysis complete.");
        return true;
    }
    uint16_t f_nscns = readU16(buf, le);

    if (memory->getBytes(addr.add(16), buf, 2) != 2) {
        if (monitor) monitor->setMessage("COFF analysis complete.");
        return true;
    }
    uint16_t f_opthdr = readU16(buf, le);

    int hdrSize = 20;
    int optionalHdrSize = f_opthdr;
    int sectionHeadersOff = hdrSize + optionalHdrSize;

    // Optional header (AOUT/PE header)
    if (optionalHdrSize > 0) {
        std::string optName = "COFF_Optional_Header";
        StructureDataType* optHdr = new StructureDataType(optName, 0, dtm);
        // Create as raw bytes for generic case
        optHdr->add(new ArrayDataType(&ByteDataType::dataType(), optionalHdrSize, 1, dtm),
                    optionalHdrSize, "optional_header", "");
        DataType* resolvedOpt = dtm->resolve(optHdr, nullptr);
        if (resolvedOpt) {
            Address optAddr(space, hdrSize);
            Data* optData = listing->createData(optAddr, resolvedOpt);
            if (optData) optData->setComment("COFF Optional Header");
            symTable->createLabel(optAddr, "COFF_OPTIONAL_HEADER", SourceType::ANALYSIS);
        }
    }

    // Section headers
    if (f_nscns > 0 && f_nscns < 1000) {
        StructureDataType* secHdr = new StructureDataType("COFF_Section_Header", 0, dtm);
        secHdr->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "s_name", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_paddr", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_vaddr", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_size", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_scnptr", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_relptr", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_lnnoptr", "");
        secHdr->add(&WordDataType::dataType(), 2, "s_nreloc", "");
        secHdr->add(&WordDataType::dataType(), 2, "s_nlnno", "");
        secHdr->add(&DWordDataType::dataType(), 4, "s_flags", "");
        DataType* resolvedSec = dtm->resolve(secHdr, nullptr);
        if (resolvedSec) {
            for (uint16_t i = 0; i < f_nscns; i++) {
                int secOff = sectionHeadersOff + i * 40;
                Address secAddr(space, secOff);

                // Read section name for comment
                uint8_t nameBuf[8] = {0};
                std::string secName = "";
                if (memory->getBytes(secAddr, nameBuf, 8) == 8) {
                    std::string n(reinterpret_cast<char*>(nameBuf), 8);
                    size_t pos = n.find('\0');
                    if (pos != std::string::npos) n = n.substr(0, pos);
                    secName = n;
                }

                Data* secData = listing->createData(secAddr, resolvedSec);
                std::string comment = "Section Header #" + std::to_string(i);
                if (!secName.empty()) comment += " (" + secName + ")";
                if (secData) secData->setComment(comment);

                std::string label = "section_" + std::to_string(i);
                symTable->createLabel(secAddr, label, SourceType::ANALYSIS);
                if (!secName.empty())
                    symTable->createLabel(secAddr, secName, SourceType::ANALYSIS);
            }
        }
    }

    // --- COFF symbol table parsing ---
    uint8_t hdrBuf[20] = {0};
    if (memory->getBytes(addr, hdrBuf, 20) != 20) {
        if (monitor) monitor->setMessage("COFF analysis complete.");
        return true;
    }
    uint32_t f_symptr = readU32(hdrBuf + 8, le);
    uint32_t f_nsyms = readU32(hdrBuf + 12, le);

    if (f_symptr > 0 && f_nsyms > 0 && f_nsyms < 100000) {
        if (monitor) monitor->setMessage("Parsing COFF symbol table...");
        uint32_t stringTableOff = f_symptr + f_nsyms * 18;

        // Read string table size
        uint8_t strSizeBuf[4] = {0};
        uint32_t stringTableSize = 0;
        if (memory->getBytes(Address(space, static_cast<int64_t>(stringTableOff)), strSizeBuf, 4) == 4) {
            stringTableSize = readU32(strSizeBuf, le);
        }

        std::vector<uint8_t> stringTable;
        if (stringTableSize > 4 && stringTableSize < 1024 * 1024) {
            stringTable.resize(stringTableSize);
            if (memory->getBytes(Address(space, static_cast<int64_t>(stringTableOff)),
                                 stringTable.data(), static_cast<int>(stringTableSize)) != static_cast<int>(stringTableSize)) {
                stringTable.clear();
            }
        }

        // Build section base address map: section index (1-based) -> virtual address
        // Section headers start at sectionHeadersOff, each 40 bytes, s_vaddr at offset 12
        std::map<uint16_t, uint64_t> sectionVAddrs;
        for (uint16_t i = 0; i < f_nscns; i++) {
            int secOff = sectionHeadersOff + i * 40;
            uint8_t secBuf[40] = {0};
            if (memory->getBytes(Address(space, secOff), secBuf, 40) == 40) {
                sectionVAddrs[i + 1] = readU32(secBuf + 12, le);
            }
        }

        int symCount = 0;
        uint32_t symOff = f_symptr;
        for (uint32_t si = 0; si < f_nsyms; si++) {
            if (monitor && monitor->isCancelled()) break;
            uint8_t symEntry[18] = {0};
            if (memory->getBytes(Address(space, static_cast<int64_t>(symOff)), symEntry, 18) != 18) break;

            // Storage class: 2=EXT (external/static), 3=EXT_DEF
            uint8_t storageClass = symEntry[16];
            // Section number: 0=undefined, >0 = section index
            int16_t sectionNum = static_cast<int16_t>(readU16(symEntry + 12, le));
            uint32_t value = readU32(symEntry + 8, le);
            uint16_t symType = readU16(symEntry + 14, le);

            // We care about function symbols: storage class EXT(2) or EXT_DEF(3),
            // section number > 0 (defined in a section), type indicating function (0x20)
            // or any symbol with a section (might be a label)
            bool isFunction = (storageClass == 2 || storageClass == 3) &&
                              sectionNum > 0 &&
                              value > 0 &&
                              (symType == 0x20 || symType == 0x00);

            if (!isFunction) {
                symOff += 18;
                continue;
            }

            // Extract symbol name
            std::string symName;
            uint8_t nameBytes[8];
            memcpy(nameBytes, symEntry, 8);
            // Check if name is in string table (first 4 bytes are 0)
            uint32_t nameIsOffset = readU32(nameBytes, le);
            auto safeStrLen = [](const char* s, size_t maxLen) -> size_t {
                size_t n = 0;
                while (n < maxLen && s[n] != '\0') ++n;
                return n;
            };

            if (nameIsOffset == 0 && !stringTable.empty()) {
                uint32_t strOff = readU32(nameBytes + 4, le);
                if (strOff > 4 && strOff < stringTableSize) {
                    const char* str = reinterpret_cast<const char*>(stringTable.data() + strOff);
                    size_t strLen = safeStrLen(str, stringTableSize - strOff);
                    if (strLen > 0) symName = std::string(str, strLen);
                }
            } else {
                // Short name: 8 bytes, null-terminated or padded
                std::string n(reinterpret_cast<char*>(nameBytes), 8);
                size_t pos = n.find('\0');
                if (pos != std::string::npos) n = n.substr(0, pos);
                // Also check for /nnnn format (long name via string table offset)
                if (!n.empty() && n[0] == '/' && n.size() > 1) {
                    try {
                        uint32_t strOff = static_cast<uint32_t>(std::stoul(n.substr(1)));
                        if (strOff > 4 && strOff < stringTableSize && !stringTable.empty()) {
                            const char* str = reinterpret_cast<const char*>(stringTable.data() + strOff);
                            size_t strLen = safeStrLen(str, stringTableSize - strOff);
                            if (strLen > 0) symName = std::string(str, strLen);
                        }
                    } catch (...) { symName = n; }
                } else {
                    symName = n;
                }
            }

            if (symName.empty()) {
                symOff += 18;
                continue;
            }

            // Compute virtual address: section base + value (offset within section)
            auto secIt = sectionVAddrs.find(static_cast<uint16_t>(sectionNum));
            if (secIt != sectionVAddrs.end()) {
                uint64_t va = secIt->second + value;
                Address symAddr(space, static_cast<int64_t>(va));

                // Only create labels, not functions (functions are created by analyzers)
                if (!symTable->hasSymbol(symAddr)) {
                    symTable->createLabel(symAddr, symName, SourceType::IMPORTED);
                    symTable->addExternalEntryPoint(symAddr);
                    ++symCount;
                }
            }

            // Skip aux entries
            uint8_t numAux = symEntry[17];
            symOff += 18 + static_cast<uint32_t>(numAux) * 18;
        }

        if (symCount > 0) {
            Msg::info(getName(), "COFF: parsed " + std::to_string(symCount) +
                      " function symbols from symbol table.");
        }
    }

    if (monitor) monitor->setMessage("COFF analysis complete.");
    return true;
}

} // namespace ghidra
