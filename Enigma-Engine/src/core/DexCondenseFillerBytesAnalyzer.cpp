#include <ghidra/DexCondenseFillerBytesAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/AlignmentDataType.h>
#include <ghidra/Data.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <cstdint>

namespace ghidra {

static constexpr uint64_t METHOD_ADDRESS = 0x50000000;

static bool isDexOrCdex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return (magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A) ||
           (magic[0] == 0x63 && magic[1] == 0x64 && magic[2] == 0x65 && magic[3] == 0x78);
}

DexCondenseFillerBytesAnalyzer::DexCondenseFillerBytesAnalyzer()
    : AbstractAnalyzer("Android DEX/CDEX Condense Filler Bytes",
                       "Condenses all filler bytes in a DEX/CDEX file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after());
    setDefaultEnablement(true);
}

bool DexCondenseFillerBytesAnalyzer::canAnalyze(Program* program) const {
    return isDexOrCdex(program);
}

bool DexCondenseFillerBytesAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DexCondenseFillerBytesAnalyzer::added(Program* program, const AddressSetView& set,
                                            TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    if (!memory || !listing) return false;

    if (monitor) monitor->setMessage("Condensing DEX filler bytes...");

    auto* space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address methodAddr(space, METHOD_ADDRESS);
    MemoryBlock* block = memory->getBlock(methodAddr);
    if (!block) return false;
    if (!block->isInitialized()) return false;

    AlignmentDataType alignType;
    Address current = block->getStart();
    Address end = block->getEnd();

    while (current.isValid() && current <= end) {
        if (monitor && monitor->isCancelled()) return false;

        if (!listing->isUndefined(current)) {
            current = current.next();
            continue;
        }

        uint8_t byteVal;
        if (memory->getBytes(current, &byteVal, 1) != 1) {
            current = current.next();
            continue;
        }
        if (byteVal != 0xFF) {
            current = current.next();
            continue;
        }

        int count = 1;
        Address runCurrent = current.next();
        while (runCurrent.isValid() && runCurrent <= end) {
            if (!listing->isUndefined(runCurrent)) break;
            if (memory->getBytes(runCurrent, &byteVal, 1) != 1) break;
            if (byteVal != 0xFF) break;
            count++;
            runCurrent = runCurrent.next();
        }

        if (count > 0) {
            listing->createData(current, &alignType, count);
        }

        current = runCurrent;
    }

    return true;
}

} // namespace ghidra
