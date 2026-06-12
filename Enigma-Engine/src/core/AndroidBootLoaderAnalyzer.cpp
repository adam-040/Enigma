#include <ghidra/AndroidBootLoaderAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/Language.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <cstring>
#include <memory>

namespace ghidra {

namespace {
    constexpr int BOOTLDR_MAGIC_SIZE = 8;
    constexpr int IMG_INFO_NAME_LENGTH = 64;
}

AndroidBootLoaderAnalyzer::AndroidBootLoaderAnalyzer()
    : AbstractAnalyzer("Android Boot Loader",
                       "Annotates the Android Boot Loader header components.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool AndroidBootLoaderAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[8] = {0};
    if (mem->getBytes(minAddr, buf, 8) != 8) return false;
    static const uint8_t bootldr[8] = { 'B', 'O', 'O', 'T', 'L', 'D', 'R', '!' };
    return std::memcmp(buf, bootldr, 8) == 0;
}

bool AndroidBootLoaderAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool AndroidBootLoaderAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    bool isLE = !program->getLanguage()->isBigEndian();
    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), isLE);

    // Read header fields
    uint64_t offset = 0;

    std::string magic = reader.readAsciiString(offset, BOOTLDR_MAGIC_SIZE);
    if (magic != "BOOTLDR!") {
        log.append("Invalid Android Boot Loader: bad magic");
        return false;
    }
    offset += BOOTLDR_MAGIC_SIZE;

    int numImages = reader.readInt(offset);
    offset += 4;

    int startOffset = reader.readInt(offset);
    offset += 4;

    int bootLoaderSize = reader.readInt(offset);
    offset += 4;

    // Read image info entries
    struct ImageInfo {
        std::string name;
        int size;
    };
    std::vector<ImageInfo> imageInfos;
    for (int i = 0; i < numImages; ++i) {
        ImageInfo info;
        info.name = reader.readAsciiString(offset, IMG_INFO_NAME_LENGTH);
        std::size_t nullPos = info.name.find('\0');
        if (nullPos != std::string::npos) {
            info.name = info.name.substr(0, nullPos);
        }
        offset += IMG_INFO_NAME_LENGTH;

        info.size = reader.readInt(offset);
        offset += 4;

        imageInfos.push_back(info);
    }

    // Create header structure
    DataTypeManager* dtm = program->getDataTypeManager();
    std::string structName = "bootloader_images_header_" + std::to_string(numImages);
    StructureDataType* headerType = new StructureDataType(structName, 0, dtm);

    headerType->add(&ByteDataType::dataType(), BOOTLDR_MAGIC_SIZE, "magic", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "num_images", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "start_offset", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "bootldr_size", nullptr);

    for (int i = 0; i < numImages; ++i) {
        StructureDataType* imgInfoType = new StructureDataType("img_info", 0, dtm);
        imgInfoType->add(&ByteDataType::dataType(), IMG_INFO_NAME_LENGTH, "magic", nullptr);
        imgInfoType->add(&DWordDataType::dataType(), 4, "size", nullptr);
        DataType* resolvedImgInfo = dtm->resolve(imgInfoType, nullptr);
        if (resolvedImgInfo) {
            headerType->add(resolvedImgInfo, 68,
                           "img_info[" + std::to_string(i) + "]", nullptr);
        }
    }

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve Android Boot Loader header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create Android Boot Loader header data");
        return false;
    }

    // Create labels
    SymbolTable* symTable = program->getSymbolTable();
    if (symTable) {
        symTable->createLabel(minAddress, "BOOTLDR_HEADER", SourceType::ANALYSIS);

        int64_t runningOffset = startOffset;
        for (int i = 0; i < numImages; ++i) {
            Address imgAddr = minAddress.add(runningOffset);
            symTable->createLabel(imgAddr, imageInfos[i].name, SourceType::ANALYSIS);
            program->getBookmarkManager()->setBookmark(imgAddr, "boot", imageInfos[i].name);
            runningOffset += imageInfos[i].size;
        }
    }

    if (monitor) {
        monitor->setMessage("Annotated Android Boot Loader at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
