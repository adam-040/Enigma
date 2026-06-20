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
                AddressSet body(addr, addr);
                funcMgr->createFunction("func_data_" + std::to_string(addr.getOffset()),
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
