#include <ghidra/DexHeaderFormatAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

static bool isDexOrCdex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return (magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A) ||
           (magic[0] == 0x63 && magic[1] == 0x64 && magic[2] == 0x65 && magic[3] == 0x78);
}

DexHeaderFormatAnalyzer::DexHeaderFormatAnalyzer()
    : AbstractAnalyzer("Android DEX/CDEX Header Format",
                       "Android Dalvik EXecutable (DEX) / Compact DEX (CDEX) Header Format.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool DexHeaderFormatAnalyzer::canAnalyze(Program* program) const {
    return isDexOrCdex(program);
}

bool DexHeaderFormatAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DexHeaderFormatAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* dtm = program->getDataTypeManager();
    auto* listing = program->getListing();
    auto* memory = program->getMemory();
    if (!dtm || !listing || !memory) return false;

    if (monitor) monitor->setMessage("Stub: DEX header struct created at 0x0");

    auto* space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address baseAddr(space, 0);

    if (listing->getDataAt(baseAddr) != nullptr) {
        log.append("data already exists at address 0x0");
        return true;
    }

    auto headerType = std::make_unique<StructureDataType>("header_item", 0, dtm);
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "magic", "");
    headerType->add(&DWordDataType::dataType(), 4, "checksum", "adler-32");
    headerType->add(new ArrayDataType(&ByteDataType::dataType(), 20, 1, dtm), 20, "signature", "SHA-1");
    headerType->add(&DWordDataType::dataType(), 4, "fileSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "headerSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "endianTag", "");
    headerType->add(&DWordDataType::dataType(), 4, "linkSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "linkOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "mapOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "stringIdsSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "stringIdsOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "typeIdsSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "typeIdsOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "protoIdsSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "protoIdsOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "fieldIdsSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "fieldIdsOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "methodIdsSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "methodIdsOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "classDefsIdsSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "classDefsIdsOffset", "");
    headerType->add(&DWordDataType::dataType(), 4, "dataSize", "");
    headerType->add(&DWordDataType::dataType(), 4, "dataOffset", "");

    DataType* resolved = dtm->resolve(headerType.get(), nullptr);
    if (!resolved) {
        log.append("Failed to resolve header_item type");
        return false;
    }

    Data* headerData = listing->createData(baseAddr, resolved);
    if (!headerData) {
        log.append("Failed to create DEX header data");
        return false;
    }

    return true;
}

} // namespace ghidra
