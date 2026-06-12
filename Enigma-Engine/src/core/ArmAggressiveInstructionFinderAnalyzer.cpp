#include <ghidra/ArmAggressiveInstructionFinderAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Language.h>
#include <ghidra/Disassembler.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

namespace ghidra {

ArmAggressiveInstructionFinderAnalyzer::ArmAggressiveInstructionFinderAnalyzer()
    : AbstractAnalyzer("ARM Aggressive Instruction Finder",
                       "Aggressively attempt to disassemble ARM/Thumb mixed code.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPrototype(true);
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after());
    setSupportsOneTimeAnalysis(true);
}

bool ArmAggressiveInstructionFinderAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    std::string name = program->getLanguage()->getProcessor().getName();
    return name == "ARM";
}

bool ArmAggressiveInstructionFinderAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

static bool tryDisassembleAt(ProgramDB* programDB, Disassembler* disassembler,
                              Listing* listing, Memory* memory,
                              const Address& addr, int maxInstrs,
                              bool isThumb, int& discovered) {
    (void)isThumb;

    uint8_t bytes[32];
    int readSize = memory->getBytes(addr, bytes, 32);
    if (readSize < 4) return false;

    std::vector<uint8_t> byteVec(bytes, bytes + readSize);
    auto instructions = disassembler->disassembleRange(byteVec, addr.getOffset(),
                                                        readSize, maxInstrs);
    if (instructions.empty()) return false;

    int offset = 0;
    for (const auto& di : instructions) {
        Address instrAddr = addr.add(offset);
        auto* inst = new Instruction(programDB, instrAddr, di.mnemonic,
                                      di.length, di.flowType);
        for (const auto& op : di.operands) {
            inst->setOperand(static_cast<int>(inst->getNumOperands()), op);
        }
        listing->addInstruction(inst);
        offset += di.length;
        ++discovered;
    }
    return true;
}

bool ArmAggressiveInstructionFinderAnalyzer::added(Program* program, const AddressSetView& set,
                                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("ARM Aggressive Instruction Finder");

    auto* programDB = dynamic_cast<ProgramDB*>(program);
    if (!programDB) return true;

    Language* lang = program->getLanguage();
    if (!lang) return true;

    bool bigEndian = lang->isBigEndian();
    auto disassembler = createDisassembler("ARM", 32, bigEndian);
    if (!disassembler) return true;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    if (!memory || !listing) return true;

    int totalDiscovered = 0;

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;
        if (!block->isExecute()) continue;

        Address blockStart = block->getStart();
        Address blockEnd = block->getEnd();
        int64_t blockSize = blockEnd.getOffset() - blockStart.getOffset() + 1;
        if (blockSize <= 0) continue;

        if (monitor) {
            monitor->setMessage(getName() + ": Scanning " + block->getName());
        }

        int64_t addrOffset = 0;
        while (addrOffset + 4 <= blockSize) {
            if (monitor && monitor->isCancelled()) break;

            Address currentAddr = blockStart.add(addrOffset);

            if (listing->isUndefined(currentAddr)) {
                int found = 0;
                if (tryDisassembleAt(programDB, disassembler.get(), listing, memory,
                                      currentAddr, 8, false, found)) {
                    addrOffset += found;
                    totalDiscovered += found;
                } else {
                    addrOffset += 2;
                }
            } else {
                Instruction* existingInstr = listing->getInstructionAt(currentAddr);
                if (existingInstr) {
                    addrOffset += existingInstr->getLength();
                } else {
                    addrOffset += 1;
                }
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Discovered " + std::to_string(totalDiscovered) +
                            " instructions in undefined regions");
    }

    return true;
}

} // namespace ghidra
