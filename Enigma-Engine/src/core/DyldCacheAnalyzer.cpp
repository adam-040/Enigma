#include <ghidra/DyldCacheAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <vector>
#include <cstring>

namespace ghidra {

static constexpr int HEADER_READ_SIZE = 0x230;

static bool isDyldCache(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[8] = {0};
    if (program->getMemory()->getBytes(addr, magic, 8) != 8) return false;
    return (magic[0] == 'd' && magic[1] == 'y' && magic[2] == 'l' && magic[3] == 'd');
}

DyldCacheAnalyzer::DyldCacheAnalyzer()
    : AbstractAnalyzer("Dyld Cache Analyzer",
                       "Analyzes the Apple dyld shared cache.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool DyldCacheAnalyzer::canAnalyze(Program* program) const {
    return isDyldCache(program);
}

bool DyldCacheAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DyldCacheAnalyzer::added(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;

    std::vector<uint8_t> headerBuf(HEADER_READ_SIZE, 0);
    Memory* mem = program->getMemory();
    int bytesRead = mem->getBytes(minAddr, headerBuf.data(), HEADER_READ_SIZE);
    if (bytesRead < 16) {
        log.append("dyld cache header too small");
        return false;
    }

    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* h = new StructureDataType("dyld_cache_header", 0, dtm);

    // Add fields sequentially; stop when struct would exceed available bytes
    auto addField = [&](DataType* dt, int fieldSize, const std::string& name) {
        if (h->getLength() + fieldSize <= bytesRead) {
            h->add(dt, fieldSize, name, "");
        }
    };

    //                       type            size  name
    h->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "magic", "");  // always present
    addField(&DWordDataType::dataType(), 4, "mappingOffset");
    addField(&DWordDataType::dataType(), 4, "mappingCount");
    addField(&DWordDataType::dataType(), 4, "imagesOffsetOld");
    addField(&DWordDataType::dataType(), 4, "imagesCountOld");
    addField(&QWordDataType::dataType(), 8, "dyldBaseAddress");
    addField(&QWordDataType::dataType(), 8, "codeSignatureOffset");
    addField(&QWordDataType::dataType(), 8, "codeSignatureSize");
    addField(&QWordDataType::dataType(), 8, "slideInfoOffset");
    addField(&QWordDataType::dataType(), 8, "slideInfoSize");
    addField(&QWordDataType::dataType(), 8, "localSymbolsOffset");
    addField(&QWordDataType::dataType(), 8, "localSymbolsSize");
    addField(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "uuid");
    addField(&QWordDataType::dataType(), 8, "cacheType");
    addField(&DWordDataType::dataType(), 4, "branchPoolsOffset");
    addField(&DWordDataType::dataType(), 4, "branchPoolsCount");
    addField(&QWordDataType::dataType(), 8, "accelerateInfoAddr");
    addField(&QWordDataType::dataType(), 8, "accelerateInfoSize");
    addField(&QWordDataType::dataType(), 8, "imagesTextOffset");
    addField(&QWordDataType::dataType(), 8, "imagesTextCount");
    addField(&QWordDataType::dataType(), 8, "patchInfoAddr");
    addField(&QWordDataType::dataType(), 8, "patchInfoSize");
    addField(&QWordDataType::dataType(), 8, "otherImageGroupAddrUnused");
    addField(&QWordDataType::dataType(), 8, "otherImageGroupSizeUnused");
    addField(&QWordDataType::dataType(), 8, "progClosuresAddr");
    addField(&QWordDataType::dataType(), 8, "progClosuresSize");
    addField(&QWordDataType::dataType(), 8, "progClosuresTrieAddr");
    addField(&QWordDataType::dataType(), 8, "progClosuresTrieSize");
    addField(&DWordDataType::dataType(), 4, "platform");
    addField(&DWordDataType::dataType(), 4, "dyld_info");
    addField(&QWordDataType::dataType(), 8, "sharedRegionStart");
    addField(&QWordDataType::dataType(), 8, "sharedRegionSize");
    addField(&QWordDataType::dataType(), 8, "maxSlide");
    addField(&QWordDataType::dataType(), 8, "dylibsImageArrayAddr");
    addField(&QWordDataType::dataType(), 8, "dylibsImageArraySize");
    addField(&QWordDataType::dataType(), 8, "dylibsTrieAddr");
    addField(&QWordDataType::dataType(), 8, "dylibsTrieSize");
    addField(&QWordDataType::dataType(), 8, "otherImageArrayAddr");
    addField(&QWordDataType::dataType(), 8, "otherImageArraySize");
    addField(&QWordDataType::dataType(), 8, "otherTrieAddr");
    addField(&QWordDataType::dataType(), 8, "otherTrieSize");
    addField(&DWordDataType::dataType(), 4, "mappingWithSlideOffset");
    addField(&DWordDataType::dataType(), 4, "mappingWithSlideCount");
    addField(&QWordDataType::dataType(), 8, "dylibsPBLStateArrayAddrUnused");
    addField(&QWordDataType::dataType(), 8, "dylibsPBLSetAddr");
    addField(&QWordDataType::dataType(), 8, "programsPBLSetPoolAddr");
    addField(&QWordDataType::dataType(), 8, "programsPBLSetPoolSize");
    addField(&QWordDataType::dataType(), 8, "programTrieAddr");
    addField(&DWordDataType::dataType(), 4, "programTrieSize");
    addField(&DWordDataType::dataType(), 4, "osVersion");
    addField(&DWordDataType::dataType(), 4, "altPlatform");
    addField(&DWordDataType::dataType(), 4, "altOsVersion");
    addField(&QWordDataType::dataType(), 8, "swiftOptsOffset");
    addField(&QWordDataType::dataType(), 8, "swiftOptsSize");
    addField(&DWordDataType::dataType(), 4, "subCacheArrayOffset");
    addField(&DWordDataType::dataType(), 4, "subCacheArrayCount");
    addField(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "symbolFileUUID");
    addField(&QWordDataType::dataType(), 8, "rosettaReadOnlyAddr");
    addField(&QWordDataType::dataType(), 8, "rosettaReadOnlySize");
    addField(&QWordDataType::dataType(), 8, "rosettaReadWriteAddr");
    addField(&QWordDataType::dataType(), 8, "rosettaReadWriteSize");
    addField(&DWordDataType::dataType(), 4, "imagesOffset");
    addField(&DWordDataType::dataType(), 4, "imagesCount");
    addField(&DWordDataType::dataType(), 4, "cacheSubType");
    addField(&DWordDataType::dataType(), 4, "padding");
    addField(&QWordDataType::dataType(), 8, "objcOptsOffset");
    addField(&QWordDataType::dataType(), 8, "objcOptsSize");
    addField(&QWordDataType::dataType(), 8, "cacheAtlasOffset");
    addField(&QWordDataType::dataType(), 8, "cacheAtlasSize");
    addField(&QWordDataType::dataType(), 8, "dynamicDataOffset");
    addField(&QWordDataType::dataType(), 8, "dynamicDataMaxSize");
    addField(&DWordDataType::dataType(), 4, "tproMappingsOffset");
    addField(&DWordDataType::dataType(), 4, "tproMappingsCount");
    addField(&QWordDataType::dataType(), 8, "functionVariantInfoAddr");
    addField(&QWordDataType::dataType(), 8, "functionVariantInfoSize");
    addField(&QWordDataType::dataType(), 8, "prewarmingDataOffset");
    addField(&QWordDataType::dataType(), 8, "prewarmingDataSize");

    DataType* resolved = dtm->resolve(h, nullptr);
    if (!resolved) {
        log.append("Failed to resolve dyld_cache_header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddr, resolved);
    if (!headerData) {
        log.append("Failed to create dyld cache header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated dyld cache header at " + minAddr.toString());
    }
    return true;
}

} // namespace ghidra
