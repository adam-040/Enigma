#include <ghidra/PefAnalyzer.h>
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
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>
#include <string>

namespace ghidra {

static constexpr int CONTAINER_HEADER_SIZE = 64;
static constexpr int SECTION_HEADER_SIZE = 28;

PefAnalyzer::PefAnalyzer()
    : AbstractBinaryFormatAnalyzer("PEF", "PEF") {
}

bool PefAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Mac OS preferred executable format (PEF)";
}

bool PefAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing PEF header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[4] = {0};
    if (memory->getBytes(addr, magic, 4) != 4) return false;
    if (magic[0] != 'J' || magic[1] != 'o' || magic[2] != 'y' || magic[3] != '!') return false;

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!dtm || !listing || !symTable) return false;

    // Container Header
    StructureDataType* pefHeader = new StructureDataType("PEF_Container_Header", 0, dtm);
    pefHeader->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "tag1", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "tag2", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "architecture", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "version", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved1", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved2", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved3", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved4", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved5", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved6", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved7", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved8", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved9", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved10", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "sectionCount", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "instSectionCount", "");
    pefHeader->add(&DWordDataType::dataType(), 4, "reserved11", "");

    DataType* resolvedHeader = dtm->resolve(pefHeader, nullptr);
    if (!resolvedHeader) return false;

    Data* headerData = listing->createData(addr, resolvedHeader);
    if (headerData) headerData->setComment("PEF Container Header");
    symTable->createLabel(addr, "PEF_HEADER", SourceType::ANALYSIS);

    // Read section count from header at offset 0x3C = 0x0C + 0x30 = byte offset in struct
    uint8_t countBuf[4] = {0};
    Address secCountAddr(space, 0x3C);
    if (memory->getBytes(secCountAddr, countBuf, 4) != 4) {
        if (monitor) monitor->setMessage("PEF analysis complete (no section count).");
        return true;
    }
    int32_t sectionCount = static_cast<int32_t>(
        (static_cast<uint32_t>(countBuf[0]) << 24) |
        (static_cast<uint32_t>(countBuf[1]) << 16) |
        (static_cast<uint32_t>(countBuf[2]) << 8) |
        static_cast<uint32_t>(countBuf[3]));

    if (sectionCount <= 0 || sectionCount > 1000) {
        if (monitor) monitor->setMessage("PEF analysis complete.");
        return true;
    }

    // Continuous struct: container header + all section headers
    StructureDataType* fullStruct = new StructureDataType("PEF_Full_Header", 0, dtm);
    DataType* contHdrType = dtm->getDataType("/PEF_Container_Header");
    if (!contHdrType) contHdrType = resolvedHeader;
    fullStruct->add(contHdrType, CONTAINER_HEADER_SIZE, "container_header", "");

    // Section headers
    StructureDataType* secHdr = new StructureDataType("PEF_Section_Header", 0, dtm);
    secHdr->add(&DWordDataType::dataType(), 4, "nameOffset", "");
    secHdr->add(&DWordDataType::dataType(), 4, "defaultAddress", "");
    secHdr->add(&DWordDataType::dataType(), 4, "totalLength", "");
    secHdr->add(&DWordDataType::dataType(), 4, "unpackedLength", "");
    secHdr->add(&DWordDataType::dataType(), 4, "containerLength", "");
    secHdr->add(&DWordDataType::dataType(), 4, "containerOffset", "");
    secHdr->add(&ByteDataType::dataType(), 1, "sectionKind", "");
    secHdr->add(&ByteDataType::dataType(), 1, "shareKind", "");
    secHdr->add(&ByteDataType::dataType(), 1, "alignment", "");
    secHdr->add(&ByteDataType::dataType(), 1, "reservedA", "");
    DataType* resolvedSecHdr = dtm->resolve(secHdr, nullptr);

    if (resolvedSecHdr) {
        fullStruct->add(resolvedSecHdr, sectionCount * SECTION_HEADER_SIZE, "section_headers", "");
    }

    DataType* resolvedFull = dtm->resolve(fullStruct, nullptr);
    if (resolvedFull) {
        Data* fullData = listing->createData(addr, resolvedFull);
        if (fullData) fullData->setComment("PEF Container Header + " + std::to_string(sectionCount) + " Section Headers");
    }

    // Create labels for each section header
    for (int i = 0; i < sectionCount; i++) {
        int64_t secOff = CONTAINER_HEADER_SIZE + i * SECTION_HEADER_SIZE;
        Address secAddr(space, static_cast<uint64_t>(secOff));
        if (!secAddr.isValid()) continue;

        // Read containerOffset for label comment context
        uint8_t offBuf[4] = {0};
        Address offAddr(space, static_cast<uint64_t>(secOff + 20));
        if (memory->getBytes(offAddr, offBuf, 4) == 4) {
            int32_t containerOff = static_cast<int32_t>(
                (static_cast<uint32_t>(offBuf[0]) << 24) |
                (static_cast<uint32_t>(offBuf[1]) << 16) |
                (static_cast<uint32_t>(offBuf[2]) << 8) |
                static_cast<uint32_t>(offBuf[3]));
            std::string labelName = "section_" + std::to_string(i);
            std::string altLabel = "section_" + std::to_string(i) + "_at_0x" +
                std::to_string(containerOff);
            symTable->createLabel(secAddr, labelName, SourceType::ANALYSIS);
            symTable->createLabel(secAddr, altLabel, SourceType::ANALYSIS);
        }
    }

    if (monitor) monitor->setMessage("PEF analysis complete: " + std::to_string(sectionCount) + " sections.");
    return true;
}

} // namespace ghidra
