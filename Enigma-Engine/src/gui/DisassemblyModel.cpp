#include "DisassemblyModel.h"
#include <ghidra/ProgramDB.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>

void DisassemblyModel::clear() {
    instructions_.clear();
    blocks_.clear();
    addressToRow_.clear();
    totalInstructions_ = 0;
}

void DisassemblyModel::buildIndex(ghidra::ProgramDB* program, ghidra::DecompInterface* decomp) {
    clear();
    if (!program || !decomp || !decomp->isOpen())
        return;

    auto* mem = program->getMemory();
    auto* af = program->getAddressFactory();
    if (!mem || !af) return;

    auto allBlocks = mem->getBlocks();

    for (auto* block : allBlocks) {
        if (!block) continue;
        int flags = block->getFlags();
        bool executable = (flags & ghidra::MemoryBlock::FLAG_EXECUTE) != 0;

        MemoryBlockInfo bi;
        bi.start = block->getStart().getUnsignedOffset();
        bi.size = block->getSize();
        bi.executable = executable;
        bi.firstRow = static_cast<int>(instructions_.size());

        if (!executable) {
            blocks_.push_back(bi);
            continue;
        }

        uint64_t addr = bi.start;
        uint64_t end = addr + bi.size;

        while (addr < end) {
            int len = decomp->instructionLengthAt(addr);
            if (len <= 0) {
                ++addr;
                continue;
            }

            InstructionEntry entry;
            entry.address = addr;
            entry.blockIndex = static_cast<int>(blocks_.size());
            addressToRow_[addr] = static_cast<int>(instructions_.size());
            instructions_.push_back(entry);

            addr += len;
        }

        bi.instrCount = static_cast<int>(instructions_.size()) - bi.firstRow;
        blocks_.push_back(bi);
    }

    totalInstructions_ = static_cast<int>(instructions_.size());
}

uint64_t DisassemblyModel::rowToAddress(int row) const {
    if (row < 0 || row >= totalInstructions_) return 0;
    return instructions_[row].address;
}

int DisassemblyModel::addressToRow(uint64_t addr) const {
    auto it = addressToRow_.find(addr);
    if (it != addressToRow_.end())
        return it->second;

    int best = -1;
    for (const auto& entry : instructions_) {
        if (entry.address <= addr)
            best = static_cast<int>(&entry - &instructions_[0]);
        else
            break;
    }
    return best;
}
