#include "ghidra/patch/PatchMemory.h"
#include "ghidra/Address.h"
#include "ghidra/MemoryBlock.h"
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace ghidra::patch {

PatchMemory::PatchMemory(std::unique_ptr<Memory> original)
    : original_(std::move(original))
{
}

bool PatchMemory::isBigEndian() const {
    return original_->isBigEndian();
}

long long PatchMemory::getSize() const {
    return original_->getSize();
}

MemoryBlock* PatchMemory::getBlock(const Address& addr) {
    return original_->getBlock(addr);
}

MemoryBlock* PatchMemory::getBlock(const std::string& blockName) {
    return original_->getBlock(blockName);
}

std::vector<MemoryBlock*> PatchMemory::getBlocks() {
    return original_->getBlocks();
}

uint8_t PatchMemory::getByte(const Address& addr) {
    uint64_t offset = static_cast<uint64_t>(addr.getOffset());
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = overlay_.find(offset);
    if (it != overlay_.end()) {
        return it->second;
    }
    return original_->getByte(addr);
}

int PatchMemory::getBytes(const Address& addr, uint8_t* dest, int size) {
    uint64_t start = static_cast<uint64_t>(addr.getOffset());
    int remaining = size;
    int totalRead = 0;

    while (remaining > 0) {
        uint64_t current = start + totalRead;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = overlay_.find(current);
        if (it != overlay_.end()) {
            dest[totalRead] = it->second;
        } else {
            Address currentAddr(addr.getAddressSpace(), static_cast<int64_t>(current));
            dest[totalRead] = original_->getByte(currentAddr);
        }
        ++totalRead;
        --remaining;
    }
    return size;
}

uint16_t PatchMemory::getShort(const Address& addr) {
    return getShort(addr, isBigEndian());
}

uint16_t PatchMemory::getShort(const Address& addr, bool bigEndian) {
    uint8_t bytes[2];
    getBytes(addr, bytes, 2);
    if (bigEndian) {
        return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
    }
    return static_cast<uint16_t>(bytes[0] | (bytes[1] << 8));
}

uint32_t PatchMemory::getInt(const Address& addr) {
    return getInt(addr, isBigEndian());
}

uint32_t PatchMemory::getInt(const Address& addr, bool bigEndian) {
    uint8_t bytes[4];
    getBytes(addr, bytes, 4);
    if (bigEndian) {
        return static_cast<uint32_t>((bytes[0] << 24) | (bytes[1] << 16) |
                                     (bytes[2] << 8) | bytes[3]);
    }
    return static_cast<uint32_t>(bytes[0] | (bytes[1] << 8) |
                                 (bytes[2] << 16) | (bytes[3] << 24));
}

uint64_t PatchMemory::getLong(const Address& addr) {
    return getLong(addr, isBigEndian());
}

uint64_t PatchMemory::getLong(const Address& addr, bool bigEndian) {
    uint8_t bytes[8];
    getBytes(addr, bytes, 8);
    if (bigEndian) {
        return (static_cast<uint64_t>(bytes[0]) << 56) |
               (static_cast<uint64_t>(bytes[1]) << 48) |
               (static_cast<uint64_t>(bytes[2]) << 40) |
               (static_cast<uint64_t>(bytes[3]) << 32) |
               (static_cast<uint64_t>(bytes[4]) << 24) |
               (static_cast<uint64_t>(bytes[5]) << 16) |
               (static_cast<uint64_t>(bytes[6]) << 8) |
               static_cast<uint64_t>(bytes[7]);
    }
    return static_cast<uint64_t>(bytes[0]) |
           (static_cast<uint64_t>(bytes[1]) << 8) |
           (static_cast<uint64_t>(bytes[2]) << 16) |
           (static_cast<uint64_t>(bytes[3]) << 24) |
           (static_cast<uint64_t>(bytes[4]) << 32) |
           (static_cast<uint64_t>(bytes[5]) << 40) |
           (static_cast<uint64_t>(bytes[6]) << 48) |
           (static_cast<uint64_t>(bytes[7]) << 56);
}

void PatchMemory::setByte(const Address& addr, uint8_t value) {
    (void)addr;
    (void)value;
    throw std::runtime_error("PatchMemory::setByte: use PatchManager instead");
}

void PatchMemory::setBytes(const Address& addr, const uint8_t* source, int size) {
    (void)addr;
    (void)source;
    (void)size;
    throw std::runtime_error("PatchMemory::setBytes: use PatchManager instead");
}

void PatchMemory::setShort(const Address& addr, uint16_t value) {
    (void)addr;
    (void)value;
    throw std::runtime_error("PatchMemory::setShort: use PatchManager instead");
}

void PatchMemory::setShort(const Address& addr, uint16_t value, bool bigEndian) {
    (void)addr;
    (void)value;
    (void)bigEndian;
    throw std::runtime_error("PatchMemory::setShort: use PatchManager instead");
}

void PatchMemory::setInt(const Address& addr, uint32_t value) {
    (void)addr;
    (void)value;
    throw std::runtime_error("PatchMemory::setInt: use PatchManager instead");
}

void PatchMemory::setInt(const Address& addr, uint32_t value, bool bigEndian) {
    (void)addr;
    (void)value;
    (void)bigEndian;
    throw std::runtime_error("PatchMemory::setInt: use PatchManager instead");
}

void PatchMemory::setLong(const Address& addr, uint64_t value) {
    (void)addr;
    (void)value;
    throw std::runtime_error("PatchMemory::setLong: use PatchManager instead");
}

void PatchMemory::setLong(const Address& addr, uint64_t value, bool bigEndian) {
    (void)addr;
    (void)value;
    (void)bigEndian;
    throw std::runtime_error("PatchMemory::setLong: use PatchManager instead");
}

void PatchMemory::applyPatch(const std::vector<uint8_t>& bytes, uint64_t address) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = 0; i < bytes.size(); ++i) {
            overlay_[address + i] = bytes[i];
        }
    }
    emitBytesChanged(address, static_cast<uint64_t>(bytes.size()));
}

void PatchMemory::removePatch(uint64_t address, uint64_t size) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (uint64_t i = 0; i < size; ++i) {
            overlay_.erase(address + i);
        }
    }
    emitBytesChanged(address, size);
}

bool PatchMemory::hasOverride(uint64_t address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return overlay_.find(address) != overlay_.end();
}

bool PatchMemory::hasOverrideRange(uint64_t address, uint64_t size) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint64_t i = 0; i < size; ++i) {
        if (overlay_.find(address + i) == overlay_.end()) return false;
    }
    return true;
}

void PatchMemory::clearOverrides() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        overlay_.clear();
    }
}

void PatchMemory::emitBytesChanged(uint64_t address, uint64_t size) {
    if (onBytesChanged_) {
        onBytesChanged_(address, size);
    }
}

} // namespace ghidra::patch
