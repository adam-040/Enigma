#include <ghidra/LzssAnalyzer.h>
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

namespace {
    constexpr int LZSS_PADDING_LENGTH = 0x16c;
}

LzssAnalyzer::LzssAnalyzer()
    : AbstractAnalyzer("LZSS Compression Annotation",
                       "Annotates an LZSS compression file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool LzssAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = program->getMemory()->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;

    uint8_t buf[8] = {0};
    if (program->getMemory()->getBytes(minAddr, buf, 8) != 8) return false;

    // Check "comp" at offset 0 and "lzss" at offset 4 (little-endian)
    return buf[0] == 'c' && buf[1] == 'o' && buf[2] == 'm' && buf[3] == 'p' &&
           buf[4] == 'l' && buf[5] == 'z' && buf[6] == 's' && buf[7] == 's';
}

bool LzssAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool LzssAnalyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    bool isLE = !program->getLanguage()->isBigEndian();
    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), isLE);

    // Validate signatures: "comp" at offset 0, "lzss" at offset 4
    uint32_t signature = reader.readUnsignedInt(0);
    uint32_t compressionType = reader.readUnsignedInt(4);
    if (signature != 0x636f6d70 || compressionType != 0x6c7a7373) {
        log.append("Invalid LZSS file: bad signature or compression type");
        return false;
    }

    // Read header fields
    uint32_t checksum = reader.readUnsignedInt(8);
    uint32_t decompressedLength = reader.readUnsignedInt(12);
    uint32_t compressedLength = reader.readUnsignedInt(16);

    // Create header structure
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("LzssCompressionHeader", 0, dtm);

    headerType->add(&DWordDataType::dataType(), 4, "signature", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "compressionType", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "checksum", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "decompressedLength", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "compressedLength", nullptr);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), LZSS_PADDING_LENGTH, 1, dtm),
                    LZSS_PADDING_LENGTH, "padding", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve LZSS compression header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create LZSS compression header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated LZSS compressed data at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
