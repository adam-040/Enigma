#include <ghidra/AARCH64PltThunkAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/Register.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <algorithm>
#include <cstdint>

namespace ghidra {

AARCH64PltThunkAnalyzer::AARCH64PltThunkAnalyzer()
    : AbstractAnalyzer("AARCH64 ELF PLT Thunks",
                       "Create AARM64 ELF PLT thunk functions",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
}

bool AARCH64PltThunkAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    const Processor& proc = program->getLanguage()->getProcessor();
    if (proc.getName() != "AARCH64") return false;
    Register* x17 = program->getRegister("x17");
    return x17 != nullptr;
}

bool AARCH64PltThunkAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool AARCH64PltThunkAnalyzer::added(Program* program, const AddressSetView& set,
                                     TaskMonitor* monitor, MessageLog& log) {
    if (monitor) monitor->setMessage(getName() + ": Analyzing PLT thunks...");

    Memory* memory = program->getMemory();
    FunctionManager* fm = program->getFunctionManager();
    Listing* listing = program->getListing();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!fm || !listing || !memory || !refMgr) return true;

    // Find .plt section
    MemoryBlock* pltBlock = nullptr;
    for (auto* block : memory->getBlocks()) {
        if (block && block->getName() == ".plt") {
            pltBlock = block;
            break;
        }
    }

    // Use name-based heuristic if no .plt section found
    if (!pltBlock) {
        if (monitor) monitor->setMessage(getName() + ": No .plt section, using name heuristic...");
        FunctionIterator it = fm->getFunctions(set, true);
        int thunkCount = 0;

        while (it.hasNext()) {
            if (monitor && monitor->isCancelled()) return false;
            Function* func = it.next();

            std::string name = func->getName();
            std::string lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find("_plt") != std::string::npos ||
                lowerName.find("plt_") != std::string::npos ||
                lowerName.find("__plt") != std::string::npos ||
                lowerName.find("plt") == 0) {
                func->setThunk(true);
                thunkCount++;

                // Try to find thunk destination via flow references
                auto refs = refMgr->getFlowReferencesFrom(func->getEntryPoint());
                for (auto* ref : refs) {
                    if (ref && ref->getReferenceType()->isJump()) {
                        Address target = ref->getToAddress();
                        Function* targetFunc = fm->getFunctionAt(target);
                        if (targetFunc) {
                            func->setThunkedFunction(targetFunc);
                        }
                        break;
                    }
                }
            }
        }

        if (monitor) {
            monitor->setMessage(getName() + ": Marked " + std::to_string(thunkCount) + " PLT thunks");
        }
        return true;
    }

    // .plt section exists — scan functions within it
    AddressSet pltSet(pltBlock->getStart(), pltBlock->getEnd());
    AddressSet searchSet = set.intersect(pltSet);

    // Remove existing function bodies from search
    {
        AddressSet toRemove;
        FunctionIterator funcIter = fm->getFunctions(searchSet, true);
        while (funcIter.hasNext()) {
            if (monitor && monitor->isCancelled()) return false;
            Function* f = funcIter.next();
            toRemove.add(f->getBody());
        }
        searchSet = searchSet.subtract(toRemove);
    }

    if (searchSet.isEmpty()) return true;

    // For each instruction in the remaining search set, try to detect PLT thunk patterns
    // Common AARCH64 PLT patterns:
    //   adrp x16, [page]  ; or adrp x17, [page]
    //   add  x16, x16, [offset] ; or add x17, x17, [page_offset]
    //   ldr  x17, [x16]  ; or br x17
    //   add  x16, x16, [offset]
    //   br   x17
    //
    // We detect these by scanning for instructions that reference x16/x17 and end with br x17

    AddressSet foundPltEntries;

    AddressRangeIterator* rangeIter = searchSet.getAddressRanges(true);
    while (rangeIter && rangeIter->hasNext()) {
        if (monitor && monitor->isCancelled()) { delete rangeIter; return false; }
        const AddressRange& range = rangeIter->next();
        Address addr = range.getMinAddress();
        Address rangeEnd = range.getMaxAddress();

        while (addr <= rangeEnd) {
            if (monitor && monitor->isCancelled()) { delete rangeIter; return false; }

            Instruction* instr = listing->getInstructionAt(addr);
            if (!instr) {
                addr = addr.add(4);
                continue;
            }

            // Check for br x17 — end of PLT thunk
            if (instr->getMnemonicString() == "br") {
                std::vector<Register*> opRegs = instr->getOperandRegisters(0);
                bool isBrX17 = false;
                for (Register* reg : opRegs) {
                    if (reg && reg->getName() == "x17") {
                        isBrX17 = true;
                        break;
                    }
                }
                if (isBrX17) {
                    // Walk backwards to find the start of this thunk
                    // The thunk likely starts after the previous function boundary
                    Address thunkStart = addr;
                    Function* containingFunc = fm->getFunctionContaining(addr);
                    if (containingFunc) {
                        thunkStart = containingFunc->getEntryPoint();
                    } else {
                        // Walk back up to 4 instructions (typical PLT thunk is 16-32 bytes)
                        Address walkAddr = addr.previous();
                        int steps = 0;
                        while (walkAddr.isValid() && steps < 8) {
                            Instruction* prevInstr = listing->getInstructionContaining(walkAddr);
                            if (!prevInstr) break;
                            if (prevInstr->getAddress() == thunkStart) break;
                            thunkStart = prevInstr->getAddress();
                            walkAddr = prevInstr->getAddress().previous();
                            steps++;
                        }
                    }

                    foundPltEntries.add(thunkStart);
                }
            }

            addr = addr.add(instr->getLength() > 0 ? instr->getLength() : 4);
        }
    }
    delete rangeIter;

    // Create thunk functions for found PLT entries
    AddressRangeIterator* createIter = foundPltEntries.getAddressRanges(true);
    while (createIter && createIter->hasNext()) {
        if (monitor && monitor->isCancelled()) { delete createIter; return false; }
        const AddressRange& range = createIter->next();
        Address entryAddr = range.getMinAddress();

        // Don't process existing non-thunk functions
        Function* existingFunc = fm->getFunctionAt(entryAddr);
        if (existingFunc) {
            existingFunc->setThunk(true);
            continue;
        }

        // Create a function body (typically 16-32 bytes for PLT stubs)
        int bodySize = 16;
        Address bodyEnd = entryAddr.add(bodySize - 1);
        AddressSet body(entryAddr, bodyEnd);

        Function* newFunc = fm->createFunction("", entryAddr, body, SourceType::ANALYSIS);
        if (newFunc) {
            newFunc->setThunk(true);

            // Look for jump references to find thunk destination
            Instruction* lastInstr = listing->getInstructionAt(entryAddr.add(bodySize - 4));
            if (lastInstr && lastInstr->getMnemonicString() == "br") {
                auto refs = refMgr->getFlowReferencesFrom(entryAddr);
                for (auto* ref : refs) {
                    if (ref && ref->getReferenceType()->isJump()) {
                        Address target = ref->getToAddress();
                        Function* targetFunc = fm->getFunctionAt(target);
                        if (targetFunc) {
                            newFunc->setThunkedFunction(targetFunc);
                        }
                        break;
                    }
                }
            }
        }
    }
    delete createIter;

    if (monitor) {
        monitor->setMessage(getName() + ": Created " +
            std::to_string(foundPltEntries.getNumAddresses()) + " PLT thunks");
    }

    return true;
}

} // namespace ghidra
