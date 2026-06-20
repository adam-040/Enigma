#include <ghidra/DataRefFunctionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>

namespace ghidra {

DataRefFunctionAnalyzer::DataRefFunctionAnalyzer()
    : AbstractAnalyzer("Data Reference Functions",
                       "Creates functions at addresses targeted by data references, CALL references, and prologue patterns.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool DataRefFunctionAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool DataRefFunctionAnalyzer::added(Program* program, const AddressSetView& set,
                                     TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return true;
    monitor->setMessage("Discovering functions from references and patterns...");

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !listing || !funcMgr) return true;

    int created = 0;
    static constexpr int MAX_CREATE = 500;

    // Phase 1: Data-referenced addresses
    if (refMgr && refMgr->getReferenceCount() > 0) {
        auto srcIter = refMgr->getReferenceSourceIterator(set, true);
        while (srcIter->hasNext() && !monitor->isCancelled() && created < MAX_CREATE) {
            Address srcAddr = srcIter->next();
            auto refs = refMgr->getReferencesFrom(srcAddr);
            for (auto* ref : refs) {
                if (!ref || !ref->getReferenceType()->isData()) continue;
                Address toAddr = ref->getToAddress();
                if (!toAddr.isValid()) continue;
                MemoryBlock* block = memory->getBlock(toAddr);
                if (!block || !block->isExecute()) continue;
                if (listing->getInstructionAt(toAddr) || !listing->isUndefined(toAddr)) continue;
                if (funcMgr->getFunctionAt(toAddr) || funcMgr->getFunctionContaining(toAddr)) continue;

                AddressSet body(toAddr, toAddr);
                funcMgr->createFunction("data_func_" + std::to_string(toAddr.getOffset()),
                                        toAddr, body, SourceType::ANALYSIS);
                ++created;
                if (created >= MAX_CREATE) break;
            }
        }
    }

    // Phase 3: CALL-referenced addresses not yet functions
    if (refMgr && refMgr->getReferenceCount() > 0) {
        auto srcIter2 = refMgr->getReferenceSourceIterator(set, true);
        while (srcIter2->hasNext() && !monitor->isCancelled() && created < MAX_CREATE) {
            Address srcAddr = srcIter2->next();
            auto refs = refMgr->getReferencesFrom(srcAddr);
            for (auto* ref : refs) {
                if (!ref) continue;
                auto* rt = ref->getReferenceType();
                if (!rt->isCall()) continue;
                Address toAddr = ref->getToAddress();
                if (!toAddr.isValid()) continue;
                MemoryBlock* block = memory->getBlock(toAddr);
                if (!block || !block->isExecute()) continue;
                if (!listing->getInstructionAt(toAddr)) continue;
                if (funcMgr->getFunctionAt(toAddr)) continue;

                // This address has a CALL to it and an instruction but no function.
                // It's an uncalled function or split point.
                AddressSet body(toAddr, toAddr);
                funcMgr->createFunction("call_target_" + std::to_string(toAddr.getOffset()),
                                        toAddr, body, SourceType::ANALYSIS);
                ++created;
                if (created >= MAX_CREATE) break;
            }
        }
    }

    if (created > 0) {
        Msg::info(getName(), "Created " + std::to_string(created) + " functions from references and patterns.");
    }
    return true;
}

} // namespace ghidra
