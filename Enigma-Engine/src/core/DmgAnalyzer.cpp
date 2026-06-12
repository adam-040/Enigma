#include <ghidra/DmgAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
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
#include <cstring>

namespace ghidra {

DmgAnalyzer::DmgAnalyzer()
    : AbstractAnalyzer("DMG Encryption Annotation",
                       "Annotates an Apple DMG encrypted image file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool DmgAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[8] = {0};
    if (mem->getBytes(minAddr, buf, 8) != 8) return false;
    static const uint8_t encrcdsa[8] = { 'e', 'n', 'c', 'r', 'c', 'd', 's', 'a' };
    static const uint8_t cdsaencr[8] = { 'c', 'd', 's', 'a', 'e', 'n', 'c', 'r' };
    return std::memcmp(buf, encrcdsa, 8) == 0 || std::memcmp(buf, cdsaencr, 8) == 0;
}

bool DmgAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DmgAnalyzer::added(Program* program, const AddressSetView& set,
                        TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true);

    // Validate V2 magic
    uint8_t sig[8];
    reader.readByteArray(0, sig, 8);
    static const uint8_t encrcdsa[8] = { 'e', 'n', 'c', 'r', 'c', 'd', 's', 'a' };
    if (std::memcmp(sig, encrcdsa, 8) != 0) {
        log.append("Invalid DMG file: bad magic");
        return false;
    }

    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("DmgHeaderV2", 0, dtm);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "signature", "");
    headerType->add(&DWordDataType::dataType(), 4, "version", "");
    headerType->add(&DWordDataType::dataType(), 4, "ivSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "unknown0", "");
    headerType->add(&DWordDataType::dataType(), 4, "unknown1", "");
    headerType->add(&DWordDataType::dataType(), 4, "unknown2", "");
    headerType->add(&DWordDataType::dataType(), 4, "unknown3", "");
    headerType->add(&DWordDataType::dataType(), 4, "unknown4", "");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "uuid", "");
    headerType->add(&DWordDataType::dataType(), 4, "blockSize", "");
    headerType->add(&QWordDataType::dataType(), 8, "dataSize", "");
    headerType->add(&QWordDataType::dataType(), 8, "dataOffset", "");

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve DmgHeaderV2 type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create DMG header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated DMG encrypted image at " + minAddress.toString());
    }
    return true;
}

} // namespace ghidra
