#include <ghidra/OatExecAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>
#include <vector>

namespace ghidra {

// OAT header constants
static const uint32_t OAT_MAGIC = 0x0A74616F; // "oat\n" as LE uint32

struct OatHeader {
    uint8_t magic[4];
    uint8_t version[4];
    uint32_t adler32_checksum;
    uint32_t instruction_set;
    uint32_t instruction_set_features_bitmap;
    uint32_t dex_file_count;
    uint32_t executable_offset;
    uint32_t i2i_bridge_offset;
    uint32_t i2c_code_bridge_offset;
    uint32_t j2i_code_bridge_offset;
    uint32_t j2c_code_bridge_offset;
    uint32_t j2i_throw_code_bridge_offset;
    uint32_t oat_pcode;
};

static bool isOatOrDex(Program* program) {
    if (!program || !program->getMemory()) return false;
    const AddressSpace* constSpace = program->getAddressFactory()->getDefaultAddressSpace();
    AddressSpace* space = const_cast<AddressSpace*>(constSpace);
    Address addr(space, 0);
    uint8_t magic[4] = {};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    uint32_t magicVal = static_cast<uint32_t>(magic[0]) |
        (static_cast<uint32_t>(magic[1]) << 8) |
        (static_cast<uint32_t>(magic[2]) << 16) |
        (static_cast<uint32_t>(magic[3]) << 24);
    return magicVal == OAT_MAGIC;
}

static uint32_t readU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

OatExecAnalyzer::OatExecAnalyzer()
    : AbstractAnalyzer("Android OAT Exec Analyzer",
                       "Analyzes the OAT Exec section for OAT or DEX files.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool OatExecAnalyzer::canAnalyze(Program* program) const {
    return isOatOrDex(program);
}

bool OatExecAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool OatExecAnalyzer::added(Program* program, const AddressSetView& set,
                             TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Analyzing OAT exec section...");

    Memory* memory = program->getMemory();
    if (!memory) return true;

    // Read OAT header at address 0
    const AddressSpace* constSpace = program->getAddressFactory()->getDefaultAddressSpace();
    AddressSpace* space = const_cast<AddressSpace*>(constSpace);
    Address base(space, 0);

    uint8_t hdr[128] = {};
    if (memory->getBytes(base, hdr, 128) < 128) {
        Msg::warn(getName(), "Could not read complete OAT header.");
        return true;
    }

    // Enable OAT version reporting
    uint32_t dexFileCount = readU32(hdr + 16);
    uint32_t execOffset = readU32(hdr + 20);

    // Create labels for the OAT executable code section
    Address execAddr(space, static_cast<int64_t>(execOffset));
    if (memory->getBlock(execAddr)) {
        program->getSymbolTable()->createLabel(execAddr, "oat_exec_start",
                                                SourceType::ANALYSIS);
    }

    BookmarkManager* bm = program->getBookmarkManager();
    bm->setBookmark(base, "INFO",
                    "OAT v" + std::to_string(hdr[4]) + "." +
                    std::to_string(hdr[5]) + "." +
                    std::to_string(hdr[6]) + "." +
                    std::to_string(hdr[7]) +
                    ", " + std::to_string(dexFileCount) + " DEX files, " +
                    "exec at 0x" + std::to_string(execOffset));

    Msg::info(getName(), "OAT analyzed: " + std::to_string(dexFileCount) + " DEX files.");
    return true;
}

} // namespace ghidra
