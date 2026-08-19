#include <ghidra/ElfAnalyzer.h>
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
#include <ghidra/CharDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolUtilities.h>
#include <ghidra/SourceType.h>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

ElfAnalyzer::ElfAnalyzer()
    : AbstractBinaryFormatAnalyzer("ELF", "ELF") {
}

bool ElfAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "ELF";
}

static uint16_t readU16(const uint8_t* buf, bool be) {
    return be
        ? (static_cast<uint16_t>(buf[0]) << 8) | buf[1]
        : (static_cast<uint16_t>(buf[1]) << 8) | buf[0];
}

static uint32_t readU32(const uint8_t* buf, bool be) {
    return be
        ? (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) |
          (static_cast<uint32_t>(buf[2]) << 8) | buf[3]
        : (static_cast<uint32_t>(buf[3]) << 24) | (static_cast<uint32_t>(buf[2]) << 16) |
          (static_cast<uint32_t>(buf[1]) << 8) | buf[0];
}

static uint64_t readU64(const uint8_t* buf, bool be) {
    if (be) {
        return (static_cast<uint64_t>(buf[0]) << 56) |
               (static_cast<uint64_t>(buf[1]) << 48) |
               (static_cast<uint64_t>(buf[2]) << 40) |
               (static_cast<uint64_t>(buf[3]) << 32) |
               (static_cast<uint64_t>(buf[4]) << 24) |
               (static_cast<uint64_t>(buf[5]) << 16) |
               (static_cast<uint64_t>(buf[6]) << 8) | buf[7];
    }
    return (static_cast<uint64_t>(buf[7]) << 56) |
           (static_cast<uint64_t>(buf[6]) << 48) |
           (static_cast<uint64_t>(buf[5]) << 40) |
           (static_cast<uint64_t>(buf[4]) << 32) |
           (static_cast<uint64_t>(buf[3]) << 24) |
           (static_cast<uint64_t>(buf[2]) << 16) |
           (static_cast<uint64_t>(buf[1]) << 8) | buf[0];
}

static uint64_t readLeb128Unsigned(const std::string& s, size_t& pos) {
    uint64_t result = 0;
    int shift = 0;
    while (pos < s.size()) {
        uint8_t b = static_cast<uint8_t>(s[pos++]);
        result |= static_cast<uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return result;
}

struct ElfSectionInfo {
    std::string name;
    uint32_t type = 0;
    uint64_t addr = 0;
    uint64_t off = 0;
    uint64_t size = 0;
};

bool ElfAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing ELF header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t ident[16] = {0};
    if (memory->getBytes(addr, ident, 16) != 16) return false;
    if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') return false;

    bool is64Bit = (ident[4] == 2);
    bool bigEndian = (ident[5] == 2);

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!dtm || !listing || !symTable) return false;

    StructureDataType* elfHeader = new StructureDataType("ELF_Header", 0, dtm);
    elfHeader->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "e_ident", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_type", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_machine", "");
    elfHeader->add(&DWordDataType::dataType(), 4, "e_version", "");
    if (is64Bit) {
        elfHeader->add(&QWordDataType::dataType(), 8, "e_entry", "");
        elfHeader->add(&QWordDataType::dataType(), 8, "e_phoff", "");
        elfHeader->add(&QWordDataType::dataType(), 8, "e_shoff", "");
    } else {
        elfHeader->add(&DWordDataType::dataType(), 4, "e_entry", "");
        elfHeader->add(&DWordDataType::dataType(), 4, "e_phoff", "");
        elfHeader->add(&DWordDataType::dataType(), 4, "e_shoff", "");
    }
    elfHeader->add(&DWordDataType::dataType(), 4, "e_flags", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_ehsize", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_phentsize", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_phnum", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_shentsize", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_shnum", "");
    elfHeader->add(&WordDataType::dataType(), 2, "e_shstrndx", "");

    DataType* resolvedHeader = dtm->resolve(elfHeader, nullptr);
    if (!resolvedHeader) return false;

    Data* headerData = listing->createData(addr, resolvedHeader);
    if (headerData) headerData->setComment("ELF Header");
    symTable->createLabel(addr, "ELF_HEADER", SourceType::ANALYSIS);

    int phoffOff = is64Bit ? 0x20 : 0x1C;
    int shoffOff = is64Bit ? 0x28 : 0x20;
    int phnumOff = is64Bit ? 0x38 : 0x2C;
    int shnumOff = is64Bit ? 0x3C : 0x30;
    int shstrOff = is64Bit ? 0x3E : 0x32;
    int phentOff = is64Bit ? 0x36 : 0x2A;
    int shentOff = is64Bit ? 0x3A : 0x2E;

    uint8_t buf8[8] = {0};

    auto readField = [&](int off, int sz) -> uint64_t {
        if (memory->getBytes(addr.add(off), buf8, sz) != sz) return 0;
        return (sz == 8) ? readU64(buf8, bigEndian) : readU32(buf8, bigEndian);
    };

    auto read16 = [&](int off) -> uint16_t {
        if (memory->getBytes(addr.add(off), buf8, 2) != 2) return 0;
        return readU16(buf8, bigEndian);
    };

    uint64_t e_phoff = readField(phoffOff, is64Bit ? 8 : 4);
    uint64_t e_shoff = readField(shoffOff, is64Bit ? 8 : 4);
    uint16_t e_phnum = read16(phnumOff);
    uint16_t e_shnum = read16(shnumOff);
    uint16_t e_shstrndx = read16(shstrOff);
    uint16_t e_phentsize = read16(phentOff);
    uint16_t e_shentsize = read16(shentOff);

    if (e_phentsize == 0) e_phentsize = is64Bit ? 56 : 32;
    if (e_shentsize == 0) e_shentsize = is64Bit ? 64 : 40;

    if (e_phnum > 0 && e_phnum < 100 && e_phoff > 0) {
        StructureDataType* phdrType = new StructureDataType(
            is64Bit ? "ElfProgramHeader64" : "ElfProgramHeader32", 0, dtm);
        if (is64Bit) {
            phdrType->add(&DWordDataType::dataType(), 4, "p_type", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_flags", "");
            phdrType->add(&QWordDataType::dataType(), 8, "p_offset", "");
            phdrType->add(&QWordDataType::dataType(), 8, "p_vaddr", "");
            phdrType->add(&QWordDataType::dataType(), 8, "p_paddr", "");
            phdrType->add(&QWordDataType::dataType(), 8, "p_filesz", "");
            phdrType->add(&QWordDataType::dataType(), 8, "p_memsz", "");
            phdrType->add(&QWordDataType::dataType(), 8, "p_align", "");
        } else {
            phdrType->add(&DWordDataType::dataType(), 4, "p_type", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_offset", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_vaddr", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_paddr", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_filesz", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_memsz", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_flags", "");
            phdrType->add(&DWordDataType::dataType(), 4, "p_align", "");
        }
        DataType* resolvedPhdr = dtm->resolve(phdrType, nullptr);
        if (resolvedPhdr) {
            for (uint16_t i = 0; i < e_phnum; i++) {
                uint64_t phOff = e_phoff + i * e_phentsize;
                Address phAddr(space, phOff);
                Data* phData = listing->createData(phAddr, resolvedPhdr);
                if (phData) phData->setComment("Program Header #" + std::to_string(i));
                symTable->createLabel(phAddr, "phdr_" + std::to_string(i), SourceType::ANALYSIS);
            }
        }
    }

std::vector<ElfSectionInfo> secs;
    if (e_shnum > 0 && e_shnum < 1000 && e_shoff > 0) {
        std::vector<std::string> sectionNames(e_shnum);
        if (e_shstrndx > 0 && e_shstrndx < e_shnum) {
            uint64_t strtabOff = e_shoff + e_shstrndx * e_shentsize;
            int shOffOff = is64Bit ? 0x18 : 0x10;
            int shSizeOff = is64Bit ? 0x20 : 0x14;
            // Read sh_offset from string table section header
            uint64_t strOff = readField(static_cast<int>(strtabOff + shOffOff), is64Bit ? 8 : 4);
            uint64_t strSize = readField(static_cast<int>(strtabOff + shSizeOff), is64Bit ? 8 : 4);
            if (strSize > 0 && strSize < 0x100000) {
                std::vector<uint8_t> strData(static_cast<size_t>(strSize));
                Address strAddr(space, strOff);
                if (memory->getBytes(strAddr, strData.data(), static_cast<int>(strSize)) == static_cast<int>(strSize)) {
                    for (uint16_t i = 0; i < e_shnum; i++) {
                        uint64_t shNameOff = e_shoff + i * e_shentsize;
                        uint32_t nameIdx = 0;
                        if (memory->getBytes(Address(space, shNameOff), buf8, 4) == 4) {
                            nameIdx = readU32(buf8, bigEndian);
                        }
                        if (nameIdx < strSize) {
                            const char* s = reinterpret_cast<const char*>(strData.data() + nameIdx);
                            size_t len = 0;
                            while (s[len] && nameIdx + len < strSize) len++;
                            if (len > 0) sectionNames[i] = std::string(s, len);
                        }
                    }
                }
            }
        }

        StructureDataType* shdrType = new StructureDataType(
            is64Bit ? "ElfSectionHeader64" : "ElfSectionHeader32", 0, dtm);
        shdrType->add(&DWordDataType::dataType(), 4, "sh_name", "");
        shdrType->add(&DWordDataType::dataType(), 4, "sh_type", "");
        if (is64Bit) {
            shdrType->add(&QWordDataType::dataType(), 8, "sh_flags", "");
            shdrType->add(&QWordDataType::dataType(), 8, "sh_addr", "");
            shdrType->add(&QWordDataType::dataType(), 8, "sh_offset", "");
            shdrType->add(&QWordDataType::dataType(), 8, "sh_size", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_link", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_info", "");
            shdrType->add(&QWordDataType::dataType(), 8, "sh_addralign", "");
            shdrType->add(&QWordDataType::dataType(), 8, "sh_entsize", "");
        } else {
            shdrType->add(&DWordDataType::dataType(), 4, "sh_flags", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_addr", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_offset", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_size", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_link", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_info", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_addralign", "");
            shdrType->add(&DWordDataType::dataType(), 4, "sh_entsize", "");
        }
        DataType* resolvedShdr = dtm->resolve(shdrType, nullptr);
        if (resolvedShdr) {
            for (uint16_t i = 0; i < e_shnum; i++) {
                uint64_t shOff = e_shoff + i * e_shentsize;
                Address shAddr(space, shOff);
                Data* shData = listing->createData(shAddr, resolvedShdr);
                std::string comment = "Section Header #" + std::to_string(i);
                if (!sectionNames[i].empty()) comment += " (" + sectionNames[i] + ")";
if (shData) shData->setComment(comment);
                symTable->createLabel(shAddr, "shdr_" + std::to_string(i), SourceType::ANALYSIS);
                if (!sectionNames[i].empty())
                    symTable->createLabel(shAddr, sectionNames[i], SourceType::ANALYSIS);
            }
        }

        // GP-5929: collect section metadata for .gnu.build.attributes markup below
        uint8_t sbuf[8] = {0};
        for (uint16_t i = 0; i < e_shnum; i++) {
            uint64_t shOff = e_shoff + i * e_shentsize;
            auto readSecField = [&](int off, int sz) -> uint64_t {
                if (memory->getBytes(Address(space, shOff + off), sbuf, sz) != sz) return 0;
                return (sz == 8) ? readU64(sbuf, bigEndian) : readU32(sbuf, bigEndian);
            };
            ElfSectionInfo s;
            s.name = sectionNames[i];
            s.type = static_cast<uint32_t>(readSecField(4, 4));
            s.addr = readSecField(is64Bit ? 0x10 : 0x0C, is64Bit ? 8 : 4);
            s.off = readSecField(is64Bit ? 0x18 : 0x10, is64Bit ? 8 : 4);
            s.size = readSecField(is64Bit ? 0x20 : 0x14, is64Bit ? 8 : 4);
            secs.push_back(s);
        }
    }

    const uint32_t SHT_GNU_ATTRIBUTES = 0x6FFFFFF5;
    const int ptrSize = is64Bit ? 8 : 4;

    for (const ElfSectionInfo& s : secs) {
        if (s.name != ".gnu.build.attributes" && s.type != SHT_GNU_ATTRIBUTES) continue;
        if (s.size == 0 || s.size > 0x1000000) continue;

        std::vector<uint8_t> secData(static_cast<size_t>(s.size));
        if (memory->getBytes(Address(space, s.off), secData.data(), static_cast<int>(s.size))
            != static_cast<int>(s.size)) {
            continue;
        }

        Address secBase(space, s.addr != 0 ? static_cast<int64_t>(s.addr)
                                           : static_cast<int64_t>(s.off));
        int totalMarked = 0;
        size_t noteOff = 0;

        while (noteOff + 12 <= secData.size()) {
            const uint8_t* p = secData.data() + noteOff;
            uint32_t nameLen = readU32(p, bigEndian);
            uint32_t descLen = readU32(p + 4, bigEndian);
            uint32_t vendorType = readU32(p + 8, bigEndian);
            if (nameLen > 0x1000 || descLen > 0x1000000) break;

            uint32_t nameAligned = (nameLen + 3) & ~3u;
            if (noteOff + 12 + nameAligned + descLen > secData.size()) break;

            const uint8_t* nameBytes = p + 12;
            const uint8_t* desc = p + 12 + nameAligned;
            std::string nameStr(reinterpret_cast<const char*>(nameBytes), nameLen);

            std::string typeStr = (vendorType == 0x100) ? "OPEN"
                                : (vendorType == 0x101) ? "FUNC" : "unknown";
            std::string idStr = "unknown";
            std::string valStr = "unknown";

            if (nameLen >= 4 && nameStr[0] == 'G' && nameStr[1] == 'A') {
                char vt = nameStr[2];
                unsigned idChar = static_cast<unsigned char>(nameStr[3]);
                size_t valueOff = 4;
                if (idChar >= 32 && idChar < 127) {
                    size_t idEnd = nameStr.find('\0', 3);
                    if (idEnd != std::string::npos) {
                        idStr = "\"" + nameStr.substr(3, idEnd - 3) + "\"";
                        valueOff = idEnd + 1;
                    }
                } else {
                    switch (idChar) {
                        case 1: idStr = "VERSION"; break;
                        case 2: idStr = "STACK_PROT"; break;
                        case 3: idStr = "RELRO"; break;
                        case 4: idStr = "STACKSIZE"; break;
                        case 5: idStr = "TOOL"; break;
                        case 6: idStr = "ABI"; break;
                        case 7: idStr = "POSITION_INDEPENDENCE"; break;
                        case 8: idStr = "SHORT_ENUM"; break;
                        default: break;
                    }
                }
                if (vt == '*') {
                    size_t pos = valueOff;
                    valStr = std::to_string(readLeb128Unsigned(nameStr, pos));
                } else if (vt == '$') {
                    size_t vEnd = nameStr.find('\0', valueOff);
                    if (vEnd != std::string::npos && vEnd > valueOff) {
                        valStr = nameStr.substr(valueOff, vEnd - valueOff);
                    }
                } else if (vt == '!') {
                    valStr = "false";
                } else if (vt == '+') {
                    valStr = "true";
                }
            }

            StructureDataType* noteType = new StructureDataType(
                "GnuBuildAttribute_" + std::to_string(nameAligned) + "_" +
                    std::to_string(descLen), 0, dtm);
            noteType->add(&DWordDataType::dataType(), 4, "namesz", "");
            noteType->add(&DWordDataType::dataType(), 4, "descsz", "");
            noteType->add(&DWordDataType::dataType(), 4, "type", "");
            noteType->add(new ArrayDataType(&CharDataType::dataType(),
                                            static_cast<int>(nameAligned), 1, dtm),
                          static_cast<int>(nameAligned), "name", "");

            int noteHdr = 12 + static_cast<int>(nameAligned);
            bool hasRange = (descLen == static_cast<uint32_t>(2 * ptrSize));
            if (hasRange) {
                noteType->add(new PointerDataType(nullptr, ptrSize, dtm), ptrSize, "start", "");
                noteType->add(new PointerDataType(nullptr, ptrSize, dtm), ptrSize, "end", "");
            } else if (descLen != 0) {
                noteType->add(new ArrayDataType(&ByteDataType::dataType(),
                                                static_cast<int>(descLen), 1, dtm),
                              static_cast<int>(descLen), "unknown", "");
            }

            DataType* resolvedNote = dtm->resolve(noteType, nullptr);
            if (!resolvedNote) {
                noteOff += 12 + nameAligned + descLen;
                continue;
            }

            Address noteAddr = secBase.add(static_cast<int64_t>(noteOff));
            Data* noteData = listing->createData(noteAddr, resolvedNote);
            if (!noteData) {
                noteOff += 12 + nameAligned + descLen;
                continue;
            }

            std::string comment = idStr + "=" + valStr;
            Address startFieldAddr;
            Address endFieldAddr;
            Address rangeStartAddr;
            Address rangeEndAddr;
            if (hasRange) {
                uint64_t rangeStart = (ptrSize == 8) ? readU64(desc, bigEndian)
                                                     : readU32(desc, bigEndian);
                uint64_t rangeEnd = (ptrSize == 8) ? readU64(desc + 8, bigEndian)
                                                   : readU32(desc + 4, bigEndian);
                rangeStartAddr = Address(space, static_cast<int64_t>(rangeStart));
                rangeEndAddr = Address(space, static_cast<int64_t>(rangeEnd) - 1);
                startFieldAddr = noteAddr.add(noteHdr);
                endFieldAddr = noteAddr.add(noteHdr + ptrSize);
                comment += ", range=" + rangeStartAddr.toString() + "-" + rangeEndAddr.toString();
            }
            noteData->setComment(comment);

            std::string label = SymbolUtilities::replaceInvalidChars(
                "gnu.build.attribute_" + typeStr + "_" + idStr + "=" + valStr, true);
            if (!label.empty()) {
                symTable->createLabel(noteAddr, label, SourceType::IMPORTED);
            }

            if (hasRange) {
                ReferenceManager* refMgr = program->getReferenceManager();
                if (refMgr) {
                    refMgr->addMemoryReference(startFieldAddr, rangeStartAddr, &RefTypes::DATA,
                                               SourceType::IMPORTED, 0);
                    refMgr->addMemoryReference(endFieldAddr, rangeEndAddr, &RefTypes::DATA,
                                               SourceType::IMPORTED, 0);
                }
            }

            noteOff += 12 + nameAligned + descLen;
            ++totalMarked;
        }

        if (totalMarked > 0 && monitor) {
            monitor->setMessage("Marked up " + std::to_string(totalMarked) +
                                " GNU build attributes");
        }
    }

    if (monitor) monitor->setMessage("ELF analysis complete.");
    return true;
}

} // namespace ghidra
