#include <ghidra/iBootImAnalyzer.h>
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
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <cstring>
#include <memory>

namespace ghidra {

namespace {
    constexpr int IBOTIM_PADDING_LENGTH = 0x28;
}

iBootImAnalyzer::iBootImAnalyzer()
    : AbstractAnalyzer("iBoot Image Annotation",
                       "Annotates an Apple iBoot image file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool iBootImAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[8] = {0};
    if (mem->getBytes(minAddr, buf, 8) != 8) return false;
    static const uint8_t expected[8] = { 'i', 'B', 'o', 'o', 't', 'I', 'm', 0 };
    return std::memcmp(buf, expected, 8) == 0;
}

bool iBootImAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool iBootImAnalyzer::added(Program* program, const AddressSetView& set,
                            TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true); // iBootIm is big-endian

    // Validate signature
    std::string sig = reader.readAsciiString(0, 8);
    if (sig.substr(0, 7) != "iBootIm") {
        log.append("Invalid iBoot image: bad signature");
        return false;
    }

    // Create header structure
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("iBootImHeader", 0, dtm);

    headerType->add(&ByteDataType::dataType(), 8, "signature", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "unknown", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "compressionType", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "format", nullptr);
    headerType->add(&WordDataType::dataType(), 2, "width", nullptr);
    headerType->add(&WordDataType::dataType(), 2, "height", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), IBOTIM_PADDING_LENGTH, 1, dtm),
                    IBOTIM_PADDING_LENGTH, "padding", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve iBoot image header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create iBoot image header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated iBoot image at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
