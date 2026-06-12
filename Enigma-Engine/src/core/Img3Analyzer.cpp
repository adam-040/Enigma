#include <ghidra/Img3Analyzer.h>
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

Img3Analyzer::Img3Analyzer()
    : AbstractAnalyzer("IMG3 Annotation",
                       "Annotates an Apple IMG3 file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool Img3Analyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[4] = {0};
    if (mem->getBytes(minAddr, buf, 4) != 4) return false;
    uint32_t magic = (static_cast<uint32_t>(buf[0]) << 24) |
                     (static_cast<uint32_t>(buf[1]) << 16) |
                     (static_cast<uint32_t>(buf[2]) << 8) |
                     buf[3];
    return magic == IMG3_SIGNATURE_INT;
}

bool Img3Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool Img3Analyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true); // IMG3 is big-endian

    // Validate magic
    uint32_t magic = reader.readUnsignedInt(0);
    if (magic != IMG3_SIGNATURE_INT) {
        log.append("Invalid IMG3 file: bad magic");
        return false;
    }

    // Create header structure (5 fields, 20 bytes)
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("Img3Header", 0, dtm);

    headerType->add(&DWordDataType::dataType(), 4, "magic", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "size", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "dataSize", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "checkArea", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "identifier", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve IMG3 header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create IMG3 header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated IMG3 image at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
