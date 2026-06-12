#include <ghidra/BootImageAnalyzer.h>
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
#include <cstring>
#include <memory>

namespace ghidra {

namespace {
    bool getMagicString(Program* program, uint8_t* buf, int size) {
        if (!program || !program->getMemory()) return false;
        Address minAddr = program->getMinAddress();
        if (!minAddr.isValid()) return false;
        return program->getMemory()->getBytes(minAddr, buf, size) == size;
    }

    void addBootHeaderV0Fields(StructureDataType* h) {
        h->add(&ByteDataType::dataType(), 8, "magic", nullptr);
        h->add(&DWordDataType::dataType(), 4, "kernel_size", nullptr);
        h->add(&DWordDataType::dataType(), 4, "kernel_addr", nullptr);
        h->add(&DWordDataType::dataType(), 4, "ramdisk_size", nullptr);
        h->add(&DWordDataType::dataType(), 4, "ramdisk_addr", nullptr);
        h->add(&DWordDataType::dataType(), 4, "second_size", nullptr);
        h->add(&DWordDataType::dataType(), 4, "second_addr", nullptr);
        h->add(&DWordDataType::dataType(), 4, "tags_addr", nullptr);
        h->add(&DWordDataType::dataType(), 4, "page_size", nullptr);
        h->add(&DWordDataType::dataType(), 4, "header_version", nullptr);
        h->add(&DWordDataType::dataType(), 4, "os_version", nullptr);
        h->add(&ByteDataType::dataType(), 16, "name", nullptr);
        h->add(&ByteDataType::dataType(), 512, "cmdline", nullptr);
        h->add(new ArrayDataType(&DWordDataType::dataType(), 8, 4, nullptr), 32, "id", nullptr);
        h->add(&ByteDataType::dataType(), 1024, "extra_cmdline", nullptr);
    }

    void addVendorBootHeaderV3Fields(StructureDataType* h) {
        h->add(&ByteDataType::dataType(), 8, "magic", nullptr);
        h->add(&DWordDataType::dataType(), 4, "header_version", nullptr);
        h->add(&DWordDataType::dataType(), 4, "page_size", nullptr);
        h->add(&DWordDataType::dataType(), 4, "kernel_addr", nullptr);
        h->add(&DWordDataType::dataType(), 4, "ramdisk_addr", nullptr);
        h->add(&DWordDataType::dataType(), 4, "vendor_ramdisk_size", nullptr);
        h->add(&ByteDataType::dataType(), 2048, "cmdline", nullptr);
        h->add(&DWordDataType::dataType(), 4, "tags_addr", nullptr);
        h->add(&ByteDataType::dataType(), 16, "name", nullptr);
        h->add(&DWordDataType::dataType(), 4, "header_size", nullptr);
        h->add(&DWordDataType::dataType(), 4, "dtb_size", nullptr);
        h->add(&DWordDataType::dataType(), 8, "dtb_addr", nullptr);
    }
}

BootImageAnalyzer::BootImageAnalyzer()
    : AbstractAnalyzer("Android Boot, Recovery, or Vendor Image Annotation",
                       "Annotates Android Boot, Recovery, or Vendor Image files.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool BootImageAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Memory* mem = program->getMemory();
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = mem->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[8] = {0};
    if (mem->getBytes(minAddr, buf, 8) != 8) return false;
    static const uint8_t bootMagic[8] = { 'A', 'N', 'D', 'R', 'O', 'I', 'D', '!' };
    static const uint8_t vndrMagic[8] = { 'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T' };
    return std::memcmp(buf, bootMagic, 8) == 0 || std::memcmp(buf, vndrMagic, 8) == 0;
}

bool BootImageAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool BootImageAnalyzer::added(Program* program, const AddressSetView& set,
                              TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    uint8_t magicBuf[8] = {0};
    if (!getMagicString(program, magicBuf, 8)) return false;

    bool isBoot = (std::memcmp(magicBuf, "ANDROID!", 8) == 0);
    bool isVendor = (std::memcmp(magicBuf, "VNDRBOOT", 8) == 0);

    if (!isBoot && !isVendor) return false;

    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = nullptr;

    if (isBoot) {
        headerType = new StructureDataType("boot_img_hdr_v0", 0, dtm);
        addBootHeaderV0Fields(headerType);
    }
    else {
        headerType = new StructureDataType("vendor_boot_img_hdr_v3", 0, dtm);
        addVendorBootHeaderV3Fields(headerType);
    }

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve boot image header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create boot image header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated Android boot image at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
