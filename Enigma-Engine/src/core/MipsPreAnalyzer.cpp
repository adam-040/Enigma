#include <ghidra/MipsPreAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/Register.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <algorithm>
#include <cmath>

namespace ghidra {

static const int NOTIFICATION_INTERVAL = 1024;

MipsPreAnalyzer::MipsPreAnalyzer()
    : AbstractAnalyzer("MIPS UnAlligned Instruction Fix",
                       "Analyze MIPS Instructions for unaligned load pairs ldl/ldr sdl/sdr lwl/lwr swl/swr.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::BLOCK_ANALYSIS.after());
    setDefaultEnablement(true);
}

bool MipsPreAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    Processor processor = program->getLanguage()->getProcessor();
    return (processor == Processor("MIPS"));
}

AddressSet MipsPreAnalyzer::removeUninitializedBlock(Program* program, const AddressSetView& set) {
    Memory* memory = program->getMemory();
    if (!memory) return set;

    AddressSet result;
    // Start with the full set
    AddressRangeIterator* iter = set.getAddressRanges(true);
    while (iter->hasNext()) {
        result.add(iter->next());
    }

    std::vector<MemoryBlock*> blocks = memory->getBlocks();
    for (MemoryBlock* block : blocks) {
        if (block && block->isInitialized() && block->isLoaded()) {
            continue;
        }
        AddressSet blocksSet;
        blocksSet.addRange(block->getStart(), block->getEnd());
        result = result.subtract(blocksSet);
    }
    return result;
}

bool MipsPreAnalyzer::checkPossiblePairInstruction(Program* program, Address addr) {
    int primeOpcode = 0;
    try {
        uint8_t b = 0;
        // LE binary has primary op-code at different location
        if (!program->getLanguage()->isBigEndian()) {
            addr = addr.add(3);
        }
        b = program->getMemory()->getByte(addr);
        primeOpcode = (static_cast<int>(b) >> 2) & 0x3f;
    } catch (const std::exception&) {
        return false;
    }

    if (primeOpcode == 34 || primeOpcode == 38 ||
        primeOpcode == 42 || primeOpcode == 46 ||
        primeOpcode == 26 || primeOpcode == 27 ||
        primeOpcode == 44 || primeOpcode == 45) {
        return true;
    }
    return false;
}

bool MipsPreAnalyzer::skipif16orR6(Program* program, Instruction* start_inst) {
    if (!start_inst) return false;

    ProgramContext* ctx = program->getProgramContext();
    if (!ctx) return false;

    bool rval = false;

    uint64_t curval1 = isamode_ ? ctx->getValue(isamode_, start_inst->getAddress()) : 0;
    uint64_t curval2 = ismbit_ ? ctx->getValue(ismbit_, start_inst->getAddress()) : 0;
    uint64_t curval3 = rel6bit_ ? ctx->getValue(rel6bit_, start_inst->getAddress()) : 0;
    uint64_t curval4 = micro16bit_ ? ctx->getValue(micro16bit_, start_inst->getAddress()) : 0;

    if ((isamode_ && micro16bit_) && curval1 == 1 && curval4 == 1) {
        rval = true;
    }
    if ((ismbit_ && micro16bit_) && curval2 == 1 && curval4 == 1) {
        rval = true;
    }
    if (rel6bit_ && curval3 == 1) {
        rval = true;
    }

    return rval;
}

void MipsPreAnalyzer::findPair(Program* program, AddressSet& pairSet,
                                Instruction* start_inst, TaskMonitor* monitor) {
    if (!start_inst) return;

    Address startAddr = start_inst->getAddress();
    // Mark the pair start in the context register
    if (pairBitRegister_) {
        try {
            program->getProgramContext()->setValue(pairBitRegister_, 1, startAddr, startAddr);
        } catch (...) {}
    }
    pairSet.add(startAddr);
}

bool MipsPreAnalyzer::added(Program* program, const AddressSetView& set,
                             TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    ProgramContext* ctx = program->getProgramContext();
    if (!ctx) return false;

    pairBitRegister_ = program->getRegister("PAIR_INSTRUCTION_FLAG");
    if (!pairBitRegister_) {
        pairBitRegister_ = ctx->getContextRegister(); // fallback
    }
    isamode_ = program->getRegister("ISA_MODE");
    ismbit_ = program->getRegister("ISAModeSwitch");
    rel6bit_ = program->getRegister("REL6");
    micro16bit_ = program->getRegister("RELP");

    AddressSet workingSet = removeUninitializedBlock(program, set);

    const uint64_t locationCount = workingSet.getNumAddresses();
    if (locationCount > NOTIFICATION_INTERVAL && monitor) {
        monitor->initialize(locationCount);
    }

    AddressRangeIterator* addresses = workingSet.getAddressRanges(true);
    AddressSet pairSet;
    int count = 0;

    while (addresses->hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        const AddressRange& range = addresses->next();
        Address addr = range.getMinAddress();
        while (addr <= range.getMaxAddress()) {
            if (monitor && monitor->isCancelled()) return false;

            if (locationCount > NOTIFICATION_INTERVAL && monitor) {
                if ((count % NOTIFICATION_INTERVAL) == 0) {
                    monitor->setMaximum(locationCount);
                    monitor->setProgress(count);
                }
                count++;
            }

            if ((addr.getOffset() & 0x3) != 0) {
                if (addr == range.getMaxAddress()) break;
                addr = addr.next();
                continue;
            }

            if (pairSet.contains(addr)) {
                if (addr == range.getMaxAddress()) break;
                addr = addr.next();
                continue;
            }

            if (!checkPossiblePairInstruction(program, addr)) {
                if (addr == range.getMaxAddress()) break;
                addr = addr.next();
                continue;
            }

            Instruction* instr = program->getListing()->getInstructionAt(addr);
            if (instr) {
                if (skipif16orR6(program, instr)) {
                    if (addr == range.getMaxAddress()) break;
                    addr = addr.next();
                    continue;
                }
                findPair(program, pairSet, instr, monitor);
            }

            if (addr == range.getMaxAddress()) break;
            addr = addr.next();
        }
    }

    if (!pairSet.isEmpty()) {
        // redoAllPairs would re-disassemble here using the Disassembler service.
        // The pair instructions have been marked in the context register so that
        // subsequent analysis passes can handle them correctly.
    }

    return true;
}

} // namespace ghidra
