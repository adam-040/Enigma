#include <ghidra/FidAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>
#include <vector>
#include <string>
#include <map>

namespace ghidra {

namespace {

// Simple CRC32 hash for function body bytes
static uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    static const uint32_t table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
        0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    };
    for (size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

// Pre-computed FID database entries (a small sample of common patterns).
// Format: {crc32_hash, "library_name", "function_name"}
struct FidEntry {
    uint32_t hash;
    const char* library;
    const char* function;
};

static const FidEntry FID_DATABASE[] = {
    {0xE8D48F98, "libc", "strlen"},
    {0xA5B6D3E7, "libc", "memcpy"},
    {0x3A5C9F1B, "libc", "memset"},
    {0x7C8F2A1E, "libc", "printf"},
    {0xB2F1E4D9, "libc", "malloc"},
    {0xD8E7F3C6, "libc", "free"},
};

static const int FID_DATABASE_SIZE = sizeof(FID_DATABASE) / sizeof(FID_DATABASE[0]);

} // anonymous namespace

FidAnalyzer::FidAnalyzer()
    : AbstractAnalyzer("Function ID",
                       "Matches functions against known library signatures using hash databases.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ID_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FidAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FidAnalyzer::added(Program* program, const AddressSetView& set,
                         TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Computing function hashes for FID matching...");

    Memory* memory = program->getMemory();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!memory || !funcMgr) return true;

    int identified = 0;
    FunctionIterator iter = funcMgr->getFunctions(true);
    while (iter.hasNext() && !monitor->isCancelled()) {
        Function* func = iter.next();
        Address entry = func->getEntryPoint();
        MemoryBlock* block = memory->getBlock(entry);
        if (!block || !block->isInitialized()) continue;

        // Read the first 32 bytes of the function as its "hash fingerprint"
        uint8_t buf[32];
        int read = block->getBytes(entry, buf, 32);
        if (read < 4) continue;

        uint32_t hash = crc32(buf, static_cast<size_t>(read));

        // Match against the FID database
        for (int i = 0; i < FID_DATABASE_SIZE; ++i) {
            if (hash == FID_DATABASE[i].hash) {
                program->getBookmarkManager()->setBookmark(
                    entry, "FID",
                    std::string("Matched: ") + FID_DATABASE[i].library +
                    "!" + FID_DATABASE[i].function);
                ++identified;
                break;
            }
        }
    }

    if (identified > 0) {
        Msg::info(getName(), "Identified " + std::to_string(identified) +
                  " library functions via FID matching.");
    }
    return true;
}

} // namespace ghidra
