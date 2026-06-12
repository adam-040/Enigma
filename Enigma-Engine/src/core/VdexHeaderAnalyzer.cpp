#include <ghidra/VdexHeaderAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>
#include <string>

namespace ghidra {

static bool isVdex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return magic[0] == 0x76 && magic[1] == 0x64 && magic[2] == 0x65 && magic[3] == 0x78;
}

VdexHeaderAnalyzer::VdexHeaderAnalyzer()
    : AbstractAnalyzer("Android VDEX Header Format",
                       "Analyzes the Android VDEX header format.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool VdexHeaderAnalyzer::canAnalyze(Program* program) const {
    return isVdex(program);
}

bool VdexHeaderAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool VdexHeaderAnalyzer::added(Program* program, const AddressSetView& set,
                                TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing VDEX header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[4] = {0};
    if (memory->getBytes(addr, magic, 4) != 4) return false;
    if (magic[0] != 0x76 || magic[1] != 0x64 || magic[2] != 0x65 || magic[3] != 0x78) return false;

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!dtm || !listing || !symTable) return false;

    // VDEX v010 header:
    // magic(4) + version(4) + number_of_dex_files(4) + dex_size(4) +
    // verifier_deps_size(4) + quickening_info_size(4)
    // = 24 bytes
    // VDEX v021 adds more fields

    uint8_t verBuf[4] = {0};
    if (memory->getBytes(addr.add(4), verBuf, 4) != 4) {
        if (monitor) monitor->setMessage("VDEX header analysis complete.");
        return true;
    }
    std::string version(reinterpret_cast<char*>(verBuf), 4);
    int hdrSize = 24; // minimum for v010

    StructureDataType* vdexHeader = new StructureDataType("VDEX_Header", 0, dtm);
    vdexHeader->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "magic", "");
    vdexHeader->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "version", "");
    vdexHeader->add(&DWordDataType::dataType(), 4, "number_of_dex_files", "");
    vdexHeader->add(&DWordDataType::dataType(), 4, "dex_size", "");
    vdexHeader->add(&DWordDataType::dataType(), 4, "verifier_deps_size", "");
    vdexHeader->add(&DWordDataType::dataType(), 4, "quickening_info_size", "");

    DataType* resolved = dtm->resolve(vdexHeader, nullptr);
    if (!resolved) {
        log.append("Failed to resolve VDEX header type");
        return false;
    }

    Data* vdexData = listing->createData(addr, resolved);
    if (vdexData) vdexData->setComment("Android VDEX Header (v" + version + ")");
    symTable->createLabel(addr, "VDEX_HEADER", SourceType::ANALYSIS);

    if (monitor) monitor->setMessage("VDEX header analysis complete.");
    return true;
}

} // namespace ghidra
