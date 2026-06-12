#include <ghidra/AppleSingleDoubleAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

AppleSingleDoubleAnalyzer::AppleSingleDoubleAnalyzer()
    : AbstractAnalyzer("AppleSingle/Double Format Analyzer",
                       "Detects and annotates AppleSingle/AppleDouble format files.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool AppleSingleDoubleAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* memory = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    uint8_t magic[4] = {0};
    if (memory->getBytes(minAddr, magic, 4) != 4) return false;
    return (magic[0] == 0x00 && magic[1] == 0x05 && magic[2] == 0x16 &&
            (magic[3] == 0x00 || magic[3] == 0x07));
}

bool AppleSingleDoubleAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool AppleSingleDoubleAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), false); // Apple Single/Double is big-endian

    // Validate magic
    uint32_t magicNumber = reader.readUnsignedInt(0);
    if (magicNumber != 0x00051600 && magicNumber != 0x00051607) {
        log.append("Invalid Apple Single/Double file: bad magic");
        return false;
    }

    // Create header struct
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("AppleSingleDouble", 0, dtm);

    headerType->add(&DWordDataType::dataType(), 4, "magicNumber", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "versionNumber", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "filler", nullptr);
    headerType->add(&WordDataType::dataType(), 2, "numberOfEntries", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve Apple Single/Double header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create Apple Single/Double header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated Apple Single/Double file at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
