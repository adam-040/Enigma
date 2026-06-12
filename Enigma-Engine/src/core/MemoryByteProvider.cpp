#include <ghidra/MemoryByteProvider.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>

namespace ghidra {

MemoryByteProvider::MemoryByteProvider(Memory* memory, const Address& baseAddress, Program* program)
    : memory_(memory), baseAddress_(baseAddress), program_(program) {
}

uint8_t MemoryByteProvider::readByte(uint64_t offset) const {
    Address addr = baseAddress_.add(static_cast<int64_t>(offset));
    uint8_t byte = 0;
    memory_->getBytes(addr, &byte, 1);
    return byte;
}

int MemoryByteProvider::readBytes(uint64_t offset, uint8_t* buf, int size) const {
    Address addr = baseAddress_.add(static_cast<int64_t>(offset));
    return memory_->getBytes(addr, buf, size);
}

uint64_t MemoryByteProvider::length() const {
    uint64_t maxLen = 0;
    auto blocks = memory_->getBlocks();
    for (auto* block : blocks) {
        if (block->getStart().getAddressSpace() != baseAddress_.getAddressSpace()) continue;
        uint64_t startOff = static_cast<uint64_t>(block->getStart().getOffset());
        uint64_t endOff = static_cast<uint64_t>(block->getEnd().getOffset());
        if (startOff <= static_cast<uint64_t>(baseAddress_.getOffset())) {
            uint64_t relEnd = endOff - static_cast<uint64_t>(baseAddress_.getOffset()) + 1;
            if (relEnd > maxLen) maxLen = relEnd;
        }
    }
    return maxLen;
}

bool MemoryByteProvider::isBigEndian() const {
    if (!program_) return false;
    auto* lang = program_->getLanguage();
    return lang && lang->isBigEndian();
}

std::string MemoryByteProvider::getName() const {
    return "MemoryByteProvider:" + baseAddress_.toString();
}

} // namespace ghidra
