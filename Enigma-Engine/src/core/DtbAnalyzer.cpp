#include <ghidra/DtbAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/Language.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

DtbAnalyzer::DtbAnalyzer()
    : AbstractAnalyzer("Device Tree (DTB/DTBO) Analyzer",
                       "Analyzes Device Tree (DTB/DTBO) files.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool DtbAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = program->getMemory()->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[4] = {0};
    if (program->getMemory()->getBytes(minAddr, buf, 4) != 4) return false;
    return buf[0] == 0xD7 && buf[1] == 0xB7 && buf[2] == 0xAB && buf[3] == 0x1E;
}

bool DtbAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DtbAnalyzer::added(Program* program, const AddressSetView& set,
                        TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true); // DTB is always big-endian

    // Validate magic
    uint32_t magic = reader.readUnsignedInt(0);
    if (magic != 0xD7B7AB1E) {
        log.append("Invalid DTB file: bad magic");
        return false;
    }

    // Create DtTableHeader struct (8 DWORDs = 32 bytes)
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("DtTableHeader", 0, dtm);

    headerType->add(&DWordDataType::dataType(), 4, "magic", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "total_size", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "header_size", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "dt_entry_size", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "dt_entry_count", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "dt_entries_offset", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "page_size", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "version", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve DTB header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create DTB header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated device tree at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
