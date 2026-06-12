#include <ghidra/FunctionStartPostAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>

namespace ghidra {

FunctionStartPostAnalyzer::FunctionStartPostAnalyzer()
    : AbstractAnalyzer("Function Start Search Post",
                       "Post-analysis variant of function start search.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::BLOCK_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FunctionStartPostAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FunctionStartPostAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Final function start sweep...");

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!memory || !listing || !funcMgr) return true;

    int found = 0;
    for (auto* block : memory->getBlocks()) {
        if (monitor->isCancelled()) break;
        if (!block->isExecute() || !block->isInitialized()) continue;

        Address addr = block->getStart();
        Address end = block->getEnd();
        while (addr <= end && !monitor->isCancelled()) {
            if (!listing->isUndefined(addr)) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }
            if (funcMgr->getFunctionContaining(addr)) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            // Check if there's a gap between defined code and undefined bytes
            // where a function likely starts
            Instruction* nextInstr = listing->getInstructionAfter(addr);
            if (!nextInstr) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }
            Address nextAddr = nextInstr->getAddress();
            int64_t gap = nextAddr.getOffset() - addr.getOffset();
            if (gap > 1 && gap <= 32) {
                // Small gap before the next instruction could be padding/nop
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            // Read first few bytes to check if they look like code
            uint8_t buf[4] = {};
            MemoryBlock* blk = memory->getBlock(addr);
            if (!blk) { try { addr = addr.add(1); } catch (...) { break; } continue; }
            int read = blk->getBytes(addr, buf, 4);
            if (read < 1) { try { addr = addr.add(1); } catch (...) { break; } continue; }

            // Heuristic: if bytes are not all zero/FF and the address is aligned,
            // create a function
            bool allZero = true, allFF = true;
            for (int i = 0; i < read; ++i) {
                if (buf[i] != 0) allZero = false;
                if (buf[i] != 0xFF) allFF = false;
            }
            if (!allZero && !allFF && (addr.getOffset() % 2 == 0)) {
                AddressSet body(addr, addr);
                funcMgr->createFunction("func_sweep_" + std::to_string(addr.getOffset()),
                                        addr, body, SourceType::ANALYSIS);
                ++found;
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            try { addr = addr.add(1); } catch (...) { break; }
        }
    }

    if (found > 0) {
        Msg::info(getName(), "Found " + std::to_string(found) + " function starts in sweep.");
    }
    return true;
}

} // namespace ghidra
