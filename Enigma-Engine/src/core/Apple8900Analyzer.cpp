#include <ghidra/Apple8900Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/Language.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

Apple8900Analyzer::Apple8900Analyzer()
    : AbstractAnalyzer("Apple 8900 Annotation",
                       "Annotates an Apple S5L8900 firmware image.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool Apple8900Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[4] = {0};
    if (mem->getBytes(minAddr, buf, 4) != 4) return false;
    return buf[0] == '8' && buf[1] == '9' && buf[2] == '0' && buf[3] == '0';
}

bool Apple8900Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Apple8900Analyzer::added(Program* program, const AddressSetView& set,
                              TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true); // Apple 8900 is big-endian

    // Validate magic
    uint32_t magic = reader.readUnsignedInt(0);
    if (magic != 0x38393030) { // "8900" as big-endian
        log.append("Invalid Apple 8900 file: bad magic");
        return false;
    }

    // Read header fields
    int sizeOfData = reader.readInt(0x10);
    int footerSigOffset = reader.readInt(0x14);
    int footerCertOffset = reader.readInt(0x18);
    int footerCertLength = reader.readInt(0x1c);

    // Create header structure
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("Apple8900Header", 0, dtm);

    headerType->add(&ByteDataType::dataType(), 4, "magic", nullptr);
    headerType->add(&ByteDataType::dataType(), 3, "version", nullptr);
    headerType->add(&ByteDataType::dataType(), 1, "encrypted", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "unknown0", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "sizeOfData", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "footerSignatureOffset", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "footerCertOffset", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "footerCertLength", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 0x20, 1, dtm), 0x20, "key1", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "unknown1", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 0x10, 1, dtm), 0x10, "key2", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 0x7b0, 1, dtm), 0x7b0, "unknown2", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve Apple 8900 header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create Apple 8900 header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated Apple 8900 firmware at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
