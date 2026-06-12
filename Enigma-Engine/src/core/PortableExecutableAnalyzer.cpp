#include <ghidra/PortableExecutableAnalyzer.h>
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
#include <ghidra/QWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace ghidra {

static constexpr uint16_t PE32_MAGIC = 0x010B;
static constexpr uint16_t PE32_PLUS_MAGIC = 0x020B;
static constexpr int PE_HEADER_SIZE = 20;

PortableExecutableAnalyzer::PortableExecutableAnalyzer()
    : AbstractBinaryFormatAnalyzer("Portable Executable", "PE") {
}

bool PortableExecutableAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

bool PortableExecutableAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing PE header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto* space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t dosHeader[64] = {0};
    if (memory->getBytes(addr, dosHeader, 64) != 64) return false;
    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') return false;

    uint32_t peOffset = static_cast<uint32_t>(dosHeader[0x3C]);
    Address peAddr(space, peOffset);

    uint8_t peSig[4] = {0};
    if (memory->getBytes(peAddr, peSig, 4) != 4) return false;
    if (peSig[0] != 'P' || peSig[1] != 'E') return false;

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();

    // --- DOS Header ---
    auto dosStruct = std::make_unique<StructureDataType>("DOS_Header", 0, dtm);
    dosStruct->add(&WordDataType::dataType(), 2, "e_magic", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_cblp", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_cp", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_crlc", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_cparhdr", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_minalloc", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_maxalloc", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_ss", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_sp", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_csum", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_ip", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_cs", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_lfarlc", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_ovno", "");
    dosStruct->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "e_res", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_oemid", "");
    dosStruct->add(&WordDataType::dataType(), 2, "e_oeminfo", "");
    dosStruct->add(new ArrayDataType(&ByteDataType::dataType(), 20, 1, dtm), 20, "e_res2", "");
    dosStruct->add(&DWordDataType::dataType(), 4, "e_lfanew", "");

    DataType* resolvedDos = dtm->resolve(dosStruct.get(), nullptr);
    if (resolvedDos) {
        Data* dosData = listing->createData(addr, resolvedDos);
        if (dosData) dosData->setComment("DOS Header");
    }
    symTable->createLabel(addr, "DOS_HEADER", SourceType::ANALYSIS);

    // --- PE Signature + File Header (combined as PE_Header) ---
    auto peStruct = std::make_unique<StructureDataType>("PE_Header", 0, dtm);
    peStruct->add(&DWordDataType::dataType(), 4, "Signature", "");
    peStruct->add(&WordDataType::dataType(), 2, "Machine", "");
    peStruct->add(&WordDataType::dataType(), 2, "NumberOfSections", "");
    peStruct->add(&DWordDataType::dataType(), 4, "TimeDateStamp", "");
    peStruct->add(&DWordDataType::dataType(), 4, "PointerToSymbolTable", "");
    peStruct->add(&DWordDataType::dataType(), 4, "NumberOfSymbols", "");
    peStruct->add(&WordDataType::dataType(), 2, "SizeOfOptionalHeader", "");
    peStruct->add(&WordDataType::dataType(), 2, "Characteristics", "");

    DataType* resolvedPe = dtm->resolve(peStruct.get(), nullptr);
    if (resolvedPe) {
        Data* peData = listing->createData(peAddr, resolvedPe);
        if (peData) peData->setComment("PE Header (Signature + File Header)");
    }
    symTable->createLabel(peAddr, "PE_HEADER", SourceType::ANALYSIS);

    // Read SizeOfOptionalHeader and NumberOfSections from the file header
    uint8_t fhBuf[PE_HEADER_SIZE] = {0};
    Address fhAddr = peAddr.add(4);
    if (memory->getBytes(fhAddr, fhBuf, PE_HEADER_SIZE) != PE_HEADER_SIZE) return true;

    uint16_t numSections = static_cast<uint16_t>(fhBuf[2]) | (static_cast<uint16_t>(fhBuf[3]) << 8);
    uint16_t sizeOfOptHdr = static_cast<uint16_t>(fhBuf[16]) | (static_cast<uint16_t>(fhBuf[17]) << 8);

    // --- Optional Header ---
    if (sizeOfOptHdr > 0) {
        Address optAddr = peAddr.add(24);
        uint8_t optMagic[2] = {0};
        memory->getBytes(optAddr, optMagic, 2);
        uint16_t magic = static_cast<uint16_t>(optMagic[0]) | (static_cast<uint16_t>(optMagic[1]) << 8);
        bool isPe32Plus = (magic == PE32_PLUS_MAGIC);

        std::string optName = isPe32Plus ? "OptionalHeader_PE32Plus" : "OptionalHeader_PE32";
        auto optStruct = std::make_unique<StructureDataType>(optName, 0, dtm);
        optStruct->add(&WordDataType::dataType(), 2, "Magic", "");

        // Standard fields (common to both PE32 and PE32+)
        optStruct->add(&ByteDataType::dataType(), 1, "MajorLinkerVersion", "");
        optStruct->add(&ByteDataType::dataType(), 1, "MinorLinkerVersion", "");
        optStruct->add(&DWordDataType::dataType(), 4, "SizeOfCode", "");
        optStruct->add(&DWordDataType::dataType(), 4, "SizeOfInitializedData", "");
        optStruct->add(&DWordDataType::dataType(), 4, "SizeOfUninitializedData", "");
        optStruct->add(&DWordDataType::dataType(), 4, "AddressOfEntryPoint", "");
        optStruct->add(&DWordDataType::dataType(), 4, "BaseOfCode", "");
        if (!isPe32Plus) {
            optStruct->add(&DWordDataType::dataType(), 4, "BaseOfData", "");
        }

        // NT-specific fields
        if (isPe32Plus) {
            optStruct->add(&QWordDataType::dataType(), 8, "ImageBase", "");
        } else {
            optStruct->add(&DWordDataType::dataType(), 4, "ImageBase", "");
        }
        optStruct->add(&DWordDataType::dataType(), 4, "SectionAlignment", "");
        optStruct->add(&DWordDataType::dataType(), 4, "FileAlignment", "");
        optStruct->add(&WordDataType::dataType(), 2, "MajorOperatingSystemVersion", "");
        optStruct->add(&WordDataType::dataType(), 2, "MinorOperatingSystemVersion", "");
        optStruct->add(&WordDataType::dataType(), 2, "MajorImageVersion", "");
        optStruct->add(&WordDataType::dataType(), 2, "MinorImageVersion", "");
        optStruct->add(&WordDataType::dataType(), 2, "MajorSubsystemVersion", "");
        optStruct->add(&WordDataType::dataType(), 2, "MinorSubsystemVersion", "");
        optStruct->add(&DWordDataType::dataType(), 4, "Win32VersionValue", "");
        optStruct->add(&DWordDataType::dataType(), 4, "SizeOfImage", "");
        optStruct->add(&DWordDataType::dataType(), 4, "SizeOfHeaders", "");
        optStruct->add(&DWordDataType::dataType(), 4, "CheckSum", "");
        optStruct->add(&WordDataType::dataType(), 2, "Subsystem", "");
        optStruct->add(&WordDataType::dataType(), 2, "DllCharacteristics", "");
        if (isPe32Plus) {
            optStruct->add(&QWordDataType::dataType(), 8, "SizeOfStackReserve", "");
            optStruct->add(&QWordDataType::dataType(), 8, "SizeOfStackCommit", "");
            optStruct->add(&QWordDataType::dataType(), 8, "SizeOfHeapReserve", "");
            optStruct->add(&QWordDataType::dataType(), 8, "SizeOfHeapCommit", "");
        } else {
            optStruct->add(&DWordDataType::dataType(), 4, "SizeOfStackReserve", "");
            optStruct->add(&DWordDataType::dataType(), 4, "SizeOfStackCommit", "");
            optStruct->add(&DWordDataType::dataType(), 4, "SizeOfHeapReserve", "");
            optStruct->add(&DWordDataType::dataType(), 4, "SizeOfHeapCommit", "");
        }
        optStruct->add(&DWordDataType::dataType(), 4, "LoaderFlags", "");
        optStruct->add(&DWordDataType::dataType(), 4, "NumberOfRvaAndSizes", "");

        // Data directory entries (16 entries, each 8 bytes: VirtualAddress + Size)
        for (int i = 0; i < 16; ++i) {
            std::string dirName = "DataDirectory_" + std::to_string(i);
            optStruct->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, dirName, "");
        }

        DataType* resolvedOpt = dtm->resolve(optStruct.get(), nullptr);
        if (resolvedOpt) {
            Data* optData = listing->createData(optAddr, resolvedOpt);
            if (optData) {
                optData->setComment(isPe32Plus ? "PE32+ Optional Header" : "PE32 Optional Header");
            }
        }
        symTable->createLabel(optAddr, "PE_OPTIONAL_HEADER", SourceType::ANALYSIS);
    }

    // --- Section Headers ---
    if (numSections > 0 && numSections < 100) {
        Address sectionAddr = peAddr.add(24 + sizeOfOptHdr);
        int sectionHeaderSize = 40;

        for (int i = 0; i < numSections; ++i) {
            if (monitor && monitor->isCancelled()) return false;

            uint8_t secBuf[40] = {0};
            Address curSecAddr = sectionAddr.add(i * sectionHeaderSize);
            if (memory->getBytes(curSecAddr, secBuf, 40) != 40) break;

            char secName[9] = {0};
            std::memcpy(secName, secBuf, 8);
            std::string name(secName);
            if (name.empty()) {
                std::ostringstream ss;
                ss << ".section_" << i;
                name = ss.str();
            }

            auto secStruct = std::make_unique<StructureDataType>("SectionHeader_" + name, 0, dtm);
            secStruct->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "Name", "");
            secStruct->add(&DWordDataType::dataType(), 4, "VirtualSize", "");
            secStruct->add(&DWordDataType::dataType(), 4, "VirtualAddress", "");
            secStruct->add(&DWordDataType::dataType(), 4, "SizeOfRawData", "");
            secStruct->add(&DWordDataType::dataType(), 4, "PointerToRawData", "");
            secStruct->add(&DWordDataType::dataType(), 4, "PointerToRelocations", "");
            secStruct->add(&DWordDataType::dataType(), 4, "PointerToLinenumbers", "");
            secStruct->add(&WordDataType::dataType(), 2, "NumberOfRelocations", "");
            secStruct->add(&WordDataType::dataType(), 2, "NumberOfLinenumbers", "");
            secStruct->add(&DWordDataType::dataType(), 4, "Characteristics", "");

            DataType* resolvedSec = dtm->resolve(secStruct.get(), nullptr);
            if (resolvedSec) {
                Data* secData = listing->createData(curSecAddr, resolvedSec);
                if (secData) {
                    secData->setComment("Section Header: " + name);
                }
            }

            // Create label at the section's raw data pointer
            uint32_t rawDataPtr = static_cast<uint32_t>(secBuf[24]) |
                (static_cast<uint32_t>(secBuf[25]) << 8) |
                (static_cast<uint32_t>(secBuf[26]) << 16) |
                (static_cast<uint32_t>(secBuf[27]) << 24);

            uint32_t rawDataSize = static_cast<uint32_t>(secBuf[16]) |
                (static_cast<uint32_t>(secBuf[17]) << 8) |
                (static_cast<uint32_t>(secBuf[18]) << 16) |
                (static_cast<uint32_t>(secBuf[19]) << 24);

            if (rawDataPtr > 0 && rawDataSize > 0) {
                Address dataStart(space, rawDataPtr);
                symTable->createLabel(dataStart, name, SourceType::ANALYSIS);
            }
        }
    }

    if (monitor) monitor->setMessage("PE analysis complete.");
    return true;
}

} // namespace ghidra
