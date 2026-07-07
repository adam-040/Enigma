#include <ghidra/FunctionStartDataPostAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/AutoNaming.h>
#include <ghidra/Msg.h>

namespace ghidra {

FunctionStartDataPostAnalyzer::FunctionStartDataPostAnalyzer()
    : AbstractAnalyzer("Function Start Search After Data",
                       "Post-data discovery variant of function start search.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FunctionStartDataPostAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FunctionStartDataPostAnalyzer::added(Program* program, const AddressSetView& set,
                                           TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Finding function starts from data references...");

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !listing || !funcMgr || !refMgr) return true;

    if (refMgr->getReferenceCount() == 0) {
        return true;
    }

    int found = 0;
    int scanned = 0;
    static constexpr int MAX_FOUND = 500;
    static constexpr int MAX_SCAN = 50000;
    AddressRangeIterator* iter = set.getAddressRanges(true);
    while (iter->hasNext() && !monitor->isCancelled() && found < MAX_FOUND && scanned < MAX_SCAN) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        while (addr <= range.getMaxAddress() && !monitor->isCancelled() && found < MAX_FOUND && scanned < MAX_SCAN) {
            ++scanned;
            if (funcMgr->getFunctionAt(addr) || funcMgr->getFunctionContaining(addr)) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            auto refsTo = refMgr->getReferencesTo(addr);
            bool hasDataRef = false;
            for (auto* ref : refsTo) {
                if (ref->getReferenceType()->isData() && memory->getBlock(addr) &&
                    memory->getBlock(addr)->isExecute()) {
                    hasDataRef = true;
                    break;
                }
            }

            if (hasDataRef && listing->isUndefined(addr)) {
                // Validate: check first byte is a plausible instruction start
                try {
                    uint8_t fb[3] = {0, 0, 0};
                    memory->getBytes(addr, fb, 3);
                    if (fb[0] == 0xCC || fb[0] == 0x00 || fb[0] == 0xFF) continue;
                    // Reject multi-byte NOP alignment padding (0F 1F ...)
                    if (fb[0] == 0x0F && fb[1] == 0x1F) continue;
                } catch (...) { continue; }

                // Validate: check we're at a function boundary
                MemoryBlock* block = memory->getBlock(addr);
                if (block && addr != block->getStart()) {
                    Address prev = addr.subtract(1);
                    if (prev.isValid()) {
                        uint8_t prevByte = 0;
                        try {
                            memory->getBytes(prev, &prevByte, 1);
                            if (prevByte != 0xCC && prevByte != 0xC3 &&
                                prevByte != 0xE9 && prevByte != 0xEB)
                                continue;
                        } catch (...) { continue; }
                    }
                }

                AddressSet body(addr, addr);
                funcMgr->createFunction(AutoNaming::nameVal("func", static_cast<uint64_t>(addr.getOffset())),
                                        addr, body, SourceType::ANALYSIS);
                ++found;
            }

            try { addr = addr.add(1); } catch (...) { break; }
        }
    }

    if (found > 0) {
        Msg::info(getName(), "Found " + std::to_string(found) + " function starts from data.");
    }
    return true;
}

} // namespace ghidra
