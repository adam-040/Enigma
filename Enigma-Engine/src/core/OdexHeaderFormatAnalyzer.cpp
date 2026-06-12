#include <ghidra/OdexHeaderFormatAnalyzer.h>
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
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>
#include <string>

namespace ghidra {

static bool isOdexDex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x79 && magic[3] == 0x0A;
}

static uint32_t read32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 24) |
           (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8) | buf[3];
}

OdexHeaderFormatAnalyzer::OdexHeaderFormatAnalyzer()
    : AbstractAnalyzer("Android ODEX Header Format",
                       "Analyzes the Android ODEX header format.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool OdexHeaderFormatAnalyzer::canAnalyze(Program* program) const {
    return isOdexDex(program);
}

bool OdexHeaderFormatAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool OdexHeaderFormatAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing ODEX header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[8] = {0};
    if (memory->getBytes(addr, magic, 8) != 8) return false;
    if (magic[0] != 0x64 || magic[1] != 0x65 || magic[2] != 0x79 || magic[3] != 0x0A) return false;

    // ODEX files are big-endian
    // ODEX header: magic(8) + dex_offset(4) + dex_length(4) + deps_offset(4) + deps_length(4) + aux_offset(4) + aux_length(4) + flags(4) + padding(4)
    // = 8+4+4+4+4+4+4+4+4 = 40 bytes

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!dtm || !listing || !symTable) return false;

    StructureDataType* odexHeader = new StructureDataType("ODEX_Header", 0, dtm);
    odexHeader->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "magic", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "dex_offset", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "dex_length", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "deps_offset", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "deps_length", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "aux_offset", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "aux_length", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "flags", "");
    odexHeader->add(&DWordDataType::dataType(), 4, "padding", "");

    DataType* resolved = dtm->resolve(odexHeader, nullptr);
    if (!resolved) {
        log.append("Failed to resolve ODEX header type");
        return false;
    }

    Data* odexData = listing->createData(addr, resolved);
    if (odexData) odexData->setComment("Android ODEX Header");
    symTable->createLabel(addr, "ODEX_HEADER", SourceType::ANALYSIS);

    // Read dex_offset, deps_offset, aux_offset for labels
    uint8_t offBuf[4] = {0};
    if (memory->getBytes(addr.add(8), offBuf, 4) == 4) {
        uint32_t dexOff = read32(offBuf);
        if (dexOff > 0) {
            Address dexAddr(space, dexOff);
            symTable->createLabel(dexAddr, "ODEX_DEX_DATA", SourceType::ANALYSIS);
        }
    }
    if (memory->getBytes(addr.add(16), offBuf, 4) == 4) {
        uint32_t depsOff = read32(offBuf);
        if (depsOff > 0) {
            Address depsAddr(space, depsOff);
            symTable->createLabel(depsAddr, "ODEX_DEPS_DATA", SourceType::ANALYSIS);
        }
    }
    if (memory->getBytes(addr.add(24), offBuf, 4) == 4) {
        uint32_t auxOff = read32(offBuf);
        if (auxOff > 0) {
            Address auxAddr(space, auxOff);
            symTable->createLabel(auxAddr, "ODEX_AUX_DATA", SourceType::ANALYSIS);
        }
    }

    if (monitor) monitor->setMessage("ODEX header analysis complete.");
    return true;
}

} // namespace ghidra
