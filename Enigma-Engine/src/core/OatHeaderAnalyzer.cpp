#include <ghidra/OatHeaderAnalyzer.h>
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

static bool isOat(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return magic[0] == 0x6F && magic[1] == 0x61 && magic[2] == 0x74 && magic[3] == 0x0A;
}

static uint32_t read32(const uint8_t* buf, bool le) {
    return le
        ? (static_cast<uint32_t>(buf[3]) << 24) | (static_cast<uint32_t>(buf[2]) << 16) |
          (static_cast<uint32_t>(buf[1]) << 8) | buf[0]
        : (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) |
          (static_cast<uint32_t>(buf[2]) << 8) | buf[3];
}

OatHeaderAnalyzer::OatHeaderAnalyzer()
    : AbstractAnalyzer("Android OAT Header Analyzer",
                       "Analyzes the Android OAT header.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool OatHeaderAnalyzer::canAnalyze(Program* program) const {
    return isOat(program);
}

bool OatHeaderAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool OatHeaderAnalyzer::added(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing OAT header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[4] = {0};
    if (memory->getBytes(addr, magic, 4) != 4) return false;
    if (magic[0] != 0x6F || magic[1] != 0x61 || magic[2] != 0x74 || magic[3] != 0x0A) return false;

    // Detect endianness from version field
    uint8_t verBuf[4] = {0};
    if (memory->getBytes(addr.add(4), verBuf, 4) != 4) return false;
    bool isLE = (verBuf[3] == 0); // '0' at end => LE

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!dtm || !listing || !symTable) return false;

    // OAT v1 header (32-bit):
    // magic(4) + version(4) + adler32(4) + inst_set(4) + inst_feat(4) + dex_count(4) +
    // exec_off(4) + reserved(4)*3 + oat_dex_files_off(4) + oat_dex_files_len(4) +
    // bss_start(4) + bss_end(4) + bss_off(4) + bss_size(4) + bss_kind(4)
    // = 4+4+4+4+4+4+4+4*3+4+4+4+4+4+4+4 = 64 bytes

    StructureDataType* oatHeader = new StructureDataType("OAT_Header", 0, dtm);
    oatHeader->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "magic", "");
    oatHeader->add(new ArrayDataType(&ByteDataType::dataType(), 4, 1, dtm), 4, "version", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "adler32_checksum", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "instruction_set", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "instruction_set_features_bitmap", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "dex_file_count", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "executable_offset", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "reserved1", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "reserved2", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "reserved3", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "oat_dex_files_offset", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "oat_dex_files_length", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "bss_start_address", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "bss_end_address", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "bss_offset", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "bss_size", "");
    oatHeader->add(&DWordDataType::dataType(), 4, "bss_kind", "");

    DataType* resolved = dtm->resolve(oatHeader, nullptr);
    if (!resolved) {
        log.append("Failed to resolve OAT header type");
        return false;
    }

    Data* oatData = listing->createData(addr, resolved);
    if (oatData) oatData->setComment("Android OAT Header");
    symTable->createLabel(addr, "OAT_HEADER", SourceType::ANALYSIS);

    // Read dex_file_count for OatDexFile markup
    uint8_t countBuf[4] = {0};
    if (memory->getBytes(addr.add(20), countBuf, 4) == 4) {
        uint32_t dexFileCount = read32(countBuf, isLE);
        if (dexFileCount > 0 && dexFileCount < 1000) {
            // Try to read oat_dex_files_offset
            uint8_t offBuf[4] = {0};
            if (memory->getBytes(addr.add(40), offBuf, 4) == 4) {
                uint32_t oatDexOff = read32(offBuf, isLE);
                if (oatDexOff > 0) {
                    // Create a simple OatDexFile entry marker
                    Address oatDexAddr(space, oatDexOff);
                    StructureDataType* odfHdr = new StructureDataType("OatDexFile", 0, dtm);
                    odfHdr->add(&DWordDataType::dataType(), 4, "dex_file_location_size", "");
                    odfHdr->add(&DWordDataType::dataType(), 4, "dex_file_location_data", "");
                    odfHdr->add(&DWordDataType::dataType(), 4, "dex_file_offset", "");
                    DataType* resolvedOdf = dtm->resolve(odfHdr, nullptr);
                    if (resolvedOdf) {
                        for (uint32_t i = 0; i < dexFileCount; i++) {
                            Address odfAddr(space, oatDexOff + i * 12);
                            Data* odfData = listing->createData(odfAddr, resolvedOdf);
                            if (odfData)
                                odfData->setComment("OatDexFile #" + std::to_string(i));
                            symTable->createLabel(odfAddr, "oat_dex_" + std::to_string(i), SourceType::ANALYSIS);
                        }
                    }
                }
            }
        }
    }

    if (monitor) monitor->setMessage("OAT header analysis complete.");
    return true;
}

} // namespace ghidra
