#include <ghidra/Img2Analyzer.h>
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
#include <ghidra/Language.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

Img2Analyzer::Img2Analyzer()
    : AbstractAnalyzer("IMG2 Annotation",
                       "Annotates an Apple IMG2 file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool Img2Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    // Read magic as big-endian int at offset 0
    uint8_t buf[4] = {0};
    if (mem->getBytes(minAddr, buf, 4) != 4) return false;
    uint32_t magic = (static_cast<uint32_t>(buf[0]) << 24) |
                     (static_cast<uint32_t>(buf[1]) << 16) |
                     (static_cast<uint32_t>(buf[2]) << 8) |
                     buf[3];
    return magic == IMG2_SIGNATURE_INT;
}

bool Img2Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Img2Analyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true); // IMG2 is big-endian

    // Validate magic
    uint32_t magic = reader.readUnsignedInt(0);
    if (magic != IMG2_SIGNATURE_INT) {
        log.append("Invalid IMG2 file: bad magic");
        return false;
    }

    // Read header fields
    int imageType = reader.readInt(4);
    int dataLenPadded = reader.readInt(0x10);
    int dataLen = reader.readInt(0x14);

    // Create header structure
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("Img2Header", 0, dtm);
    headerType->add(&DWordDataType::dataType(), 4, "signature", "");
    headerType->add(&DWordDataType::dataType(), 4, "imageType", "");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 2, 1, dtm), 2, "unknown0", "");
    headerType->add(&WordDataType::dataType(), 2, "securityEpoch", "");
    headerType->add(&DWordDataType::dataType(), 4, "flags1", "");
    headerType->add(&DWordDataType::dataType(), 4, "dataLenPadded", "");
    headerType->add(&DWordDataType::dataType(), 4, "dataLen", "");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "unknown1", "");
    headerType->add(&DWordDataType::dataType(), 4, "flags2", "");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 0x40, 1, dtm), 0x40, "reserved", "");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "unknown2", "");
    headerType->add(&DWordDataType::dataType(), 4, "headerChecksum", "");
    headerType->add(&DWordDataType::dataType(), 4, "checksum2", "");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 0x394, 1, dtm), 0x394, "unknown3", "");

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve Img2Header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create IMG2 header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated IMG2 header at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
