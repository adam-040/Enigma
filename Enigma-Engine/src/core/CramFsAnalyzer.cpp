#include <ghidra/CramFsAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/LongDataType.h>
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

CramFsAnalyzer::CramFsAnalyzer()
    : AbstractAnalyzer("CramFS Analyzer",
                       "Annotates CramFS binaries",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
}

bool CramFsAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[4] = {0};
    if (mem->getBytes(minAddr, buf, 4) != 4) return false;
    uint32_t magic = (static_cast<uint32_t>(buf[3]) << 24) |
                     (static_cast<uint32_t>(buf[2]) << 16) |
                     (static_cast<uint32_t>(buf[1]) << 8) |
                     buf[0];
    return magic == CRAMFS_MAGIC;
}

bool CramFsAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool CramFsAnalyzer::added(Program* program, const AddressSetView& set,
                           TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    bool isLE = !program->getLanguage()->isBigEndian();

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), isLE);

    uint32_t magic = reader.readUnsignedInt(0);
    if (magic != CRAMFS_MAGIC) return false;

    // Create superblock structure
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* superType = new StructureDataType("CramFsSuper", 0, dtm);
    superType->add(&ByteDataType::dataType(), HEADER_STRING_LENGTH, "signature", nullptr);
    superType->add(&LongDataType::dataType(), "fsid", nullptr);
    superType->add(&LongDataType::dataType(), "size", nullptr);
    superType->add(&LongDataType::dataType(), "flags", nullptr);
    superType->add(&LongDataType::dataType(), "future", nullptr);
    superType->add(&ByteDataType::dataType(), "signature2", nullptr);
    superType->add(&LongDataType::dataType(), "rootOffset", nullptr);

    // Create data at minAddress
    DataType* resolvedType = dtm->resolve(superType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve CramFS superblock type");
        return false;
    }

    Data* dataObj = program->getListing()->createData(minAddress, resolvedType);
    if (!dataObj) {
        log.append("Failed to create CramFS superblock data");
        return false;
    }

    return true;
}

} // namespace ghidra
