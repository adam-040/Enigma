#include <ghidra/FBPK_Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <memory>

namespace ghidra {

namespace {
    constexpr int V1_VERSION_MAX_LENGTH = 68;
    constexpr int V2_STRING1_MAX_LENGTH = 16;
    constexpr int V2_STRING2_MAX_LENGTH = 68;
}

FBPK_Analyzer::FBPK_Analyzer()
    : AbstractAnalyzer("Android FBPK Analyzer",
                       "Analyzes the Android FBPK (Firmware Package) format.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool FBPK_Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(minAddr, magic, 4) != 4) return false;
    return magic[0] == 'F' && magic[1] == 'B' && magic[2] == 'P' && magic[3] == 'K';
}

bool FBPK_Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool FBPK_Analyzer::added(Program* program, const AddressSetView& set,
                           TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), false); // FBPK is little-endian

    // Read common fields
    uint32_t rawMagic = reader.readUnsignedInt(0);
    if (rawMagic != 0x4B504246) { // "FBPK"
        log.append("Invalid FBPK file: bad magic");
        return false;
    }

    int version = reader.readInt(4);
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = nullptr;

    if (version == 1) {
        headerType = new StructureDataType("FBPKv1", 0, dtm);
        headerType->add(&ByteDataType::dataType(), 4, "magic", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "version", nullptr);
        headerType->add(&ByteDataType::dataType(), V1_VERSION_MAX_LENGTH, "string", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "partitionCount", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "size", nullptr);
    }
    else if (version == 2) {
        headerType = new StructureDataType("FBPKv2", 0, dtm);
        headerType->add(&ByteDataType::dataType(), 4, "magic", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "version", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "unknown1", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "unknown2", nullptr);
        headerType->add(&ByteDataType::dataType(), V2_STRING1_MAX_LENGTH, "string1", nullptr);
        headerType->add(&ByteDataType::dataType(), V2_STRING2_MAX_LENGTH, "string2", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "unknown3", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "partitionCount", nullptr);
        headerType->add(&DWordDataType::dataType(), 4, "size", nullptr);
    }
    else {
        log.append("Unsupported FBPK version: " + std::to_string(version));
        return false;
    }

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve FBPK header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create FBPK header data");
        return false;
    }

    if (monitor) monitor->setMessage("Analyzing FBPK firmware package...");
    return true;
}

} // namespace ghidra
