#include <ghidra/MachoFunctionStartsAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AutoNaming.h>
#include <ghidra/MessageLog.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

static uint64_t readULEB128(const uint8_t* data, int& pos, int maxSize) {
    uint64_t result = 0;
    int shift = 0;
    while (pos < maxSize) {
        uint8_t byte = data[pos++];
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    return result;
}

MachoFunctionStartsAnalyzer::MachoFunctionStartsAnalyzer()
    : AbstractAnalyzer("Mach-O Function Starts",
                       "An analyzer for discovering functions via the Mach-O LC_FUNCTION_STARTS load command",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::FUNCTION_ID_ANALYSIS.after());
    setSupportsOneTimeAnalysis(true);
}

bool MachoFunctionStartsAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    const std::string& format = program->getExecutableFormat();
    return format.find("Mach-O") != std::string::npos ||
           format.find("dyld") != std::string::npos;
}

bool MachoFunctionStartsAnalyzer::added(Program* program, const AddressSetView& set,
                                         TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Address imageBase = program->getImageBase();
    if (!memory || !symTable) return true;

    // Read Mach-O header: first 4 bytes = magic, then 4 bytes = cputype,
    // then 4 bytes = cpusubtype, then 4 bytes = filetype,
    // then 4 bytes = ncmds, then 4 bytes = sizeofcmds
    uint8_t header[28];
    if (memory->getBytes(imageBase, header, 28) != 28) return true;

    uint32_t magic = (static_cast<uint32_t>(header[0]) << 0) |
                     (static_cast<uint32_t>(header[1]) << 8) |
                     (static_cast<uint32_t>(header[2]) << 16) |
                     (static_cast<uint32_t>(header[3]) << 24);

    bool is64 = (magic == 0xFEEDFACF || magic == 0xCFFAEDFE);
    int headerSize = is64 ? 32 : 28;

    int ncmds;
    if (is64) {
        // 64-bit: offset 16 = ncmds (4 bytes)
        ncmds = (static_cast<int>(header[16]) << 0) |
                (static_cast<int>(header[17]) << 8) |
                (static_cast<int>(header[18]) << 16) |
                (static_cast<int>(header[19]) << 24);
    } else {
        // 32-bit: offset 16 = ncmds (4 bytes)
        ncmds = (static_cast<int>(header[16]) << 0) |
                (static_cast<int>(header[17]) << 8) |
                (static_cast<int>(header[18]) << 16) |
                (static_cast<int>(header[19]) << 24);
    }

    if (ncmds <= 0) return true;

    // Iterate load commands to find LC_FUNCTION_STARTS (0x26)
    Address loadCmdAddr = imageBase.add(headerSize);
    uint64_t funcStartsDataOff = 0;
    uint64_t funcStartsDataSize = 0;

    for (int i = 0; i < ncmds; ++i) {
        if (monitor && monitor->isCancelled()) return true;

        uint8_t lcBuf[8];
        if (memory->getBytes(loadCmdAddr, lcBuf, 8) != 8) return true;

        uint32_t cmd = (static_cast<uint32_t>(lcBuf[0]) << 0) |
                       (static_cast<uint32_t>(lcBuf[1]) << 8) |
                       (static_cast<uint32_t>(lcBuf[2]) << 16) |
                       (static_cast<uint32_t>(lcBuf[3]) << 24);
        uint32_t cmdsize = (static_cast<uint32_t>(lcBuf[4]) << 0) |
                           (static_cast<uint32_t>(lcBuf[5]) << 8) |
                           (static_cast<uint32_t>(lcBuf[6]) << 16) |
                           (static_cast<uint32_t>(lcBuf[7]) << 24);

        if (cmd == 0x26) {
            // LC_FUNCTION_STARTS: dataoff (4) + datasize (4) at offset 8
            uint8_t fsBuf[8];
            if (memory->getBytes(loadCmdAddr.add(8), fsBuf, 8) == 8) {
                funcStartsDataOff = (static_cast<uint64_t>(fsBuf[0]) << 0) |
                                    (static_cast<uint64_t>(fsBuf[1]) << 8) |
                                    (static_cast<uint64_t>(fsBuf[2]) << 16) |
                                    (static_cast<uint64_t>(fsBuf[3]) << 24);
                if (is64) {
                    // 64-bit has 32-bit dataoff but we keep it as uint64
                }
                funcStartsDataSize = (static_cast<uint64_t>(fsBuf[4]) << 0) |
                                     (static_cast<uint64_t>(fsBuf[5]) << 8) |
                                     (static_cast<uint64_t>(fsBuf[6]) << 16) |
                                     (static_cast<uint64_t>(fsBuf[7]) << 24);
            }
            break;
        }

        loadCmdAddr = loadCmdAddr.add(cmdsize);
    }

    if (funcStartsDataOff == 0 || funcStartsDataSize == 0) return true;

    // Find linkedit segment to resolve file offset to address
    MemoryBlock* block = memory->getBlock("__LINKEDIT");
    if (!block) {
        // Try to find by scanning blocks
        for (auto* blk : memory->getBlocks()) {
            if (blk->getName().find("LINKEDIT") != std::string::npos) {
                block = blk;
                break;
            }
        }
    }

    // If no LINKEDIT block, the data might be file-relative.
    // In memory, Mach-O is typically loaded with __TEXT at imageBase
    // and __LINKEDIT follows. We try to read the data directly at
    // imageBase + dataoff (file offset mapping).
    Address startOfData;
    if (block) {
        // __LINKEDIT starts at some file offset; dataoff is relative to file start
        // We approximate: startOfData = block->getStart() + (dataoff - blockFileOffset)
        // Without knowing block's file offset, just use imageBase + dataoff
        startOfData = imageBase.add(static_cast<int64_t>(funcStartsDataOff));
    } else {
        startOfData = imageBase.add(static_cast<int64_t>(funcStartsDataOff));
    }

    // Read and decode ULEB128 function start offsets
    std::vector<uint8_t> funcData(static_cast<size_t>(funcStartsDataSize));
    if (memory->getBytes(startOfData, funcData.data(), static_cast<int>(funcStartsDataSize))
        != static_cast<int>(funcStartsDataSize)) {
        return true;
    }

    if (monitor) {
        monitor->initialize(static_cast<int>(funcStartsDataSize));
    }

    uint64_t cumulativeOffset = 0;
    int pos = 0;
    int funcCount = 0;

    while (pos < static_cast<int>(funcStartsDataSize)) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(pos);

        int oldPos = pos;
        uint64_t delta = readULEB128(funcData.data(), pos, static_cast<int>(funcStartsDataSize));
        if (pos == oldPos) break; // no progress

        cumulativeOffset += delta;
        Address funcAddr = imageBase.add(static_cast<int64_t>(cumulativeOffset));

        std::string labelName = AutoNaming::name("func", funcAddr);
        symTable->createLabel(funcAddr, labelName, SourceType::ANALYSIS);
        ++funcCount;
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Created " + std::to_string(funcCount) + " function start labels");
    }

    return true;
}

} // namespace ghidra
