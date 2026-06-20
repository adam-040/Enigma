/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Memory.cpp
/// \brief Memory model implementation
#include <ghidra/Memory.h>

namespace ghidra {

bool Memory::isValidMemoryBlockName(const std::string& name) {
    if (name.empty()) return false;
    for (char c : name) {
        if (c < 0x20) return false;
    }
    return true;
}

bool Memory::isExternalBlockAddress(const Address& addr) {
    MemoryBlock* block = getBlock(addr);
    return block != nullptr && block->isExternalBlock();
}

uint8_t Memory::getByte(const Address& addr) {
    MemoryBlock* block = getBlock(addr);
    if (!block) throw MemoryAccessException("Address not in any memory block");
    return block->getByte(addr);
}

int Memory::getBytes(const Address& addr, uint8_t* dest, int size) {
    MemoryBlock* block = getBlock(addr);
    if (!block) throw MemoryAccessException("Starting address not in any memory block");
    return block->getBytes(addr, dest, size);
}

void Memory::setByte(const Address& addr, uint8_t value) {
    MemoryBlock* block = getBlock(addr);
    if (!block || !block->isWrite()) {
        throw MemoryAccessException("Writing is not allowed");
    }
    block->putByte(addr, value);
}

void Memory::setBytes(const Address& addr, const uint8_t* source, int size) {
    MemoryBlock* block = getBlock(addr);
    if (!block || !block->isWrite()) {
        throw MemoryAccessException("Writing is not allowed");
    }
    block->putBytes(addr, source, size);
}

uint16_t Memory::getShort(const Address& addr) {
    return getShort(addr, isBigEndian());
}

uint16_t Memory::getShort(const Address& addr, bool bigEndian) {
    uint8_t buf[2];
    int n = getBytes(addr, buf, 2);
    if (n < 2) throw MemoryAccessException("Not enough bytes for short");
    return bigEndian
        ? static_cast<uint16_t>((buf[0] << 8) | buf[1])
        : static_cast<uint16_t>(buf[0] | (buf[1] << 8));
}

uint32_t Memory::getInt(const Address& addr) {
    return getInt(addr, isBigEndian());
}

uint32_t Memory::getInt(const Address& addr, bool bigEndian) {
    uint8_t buf[4];
    int n = getBytes(addr, buf, 4);
    if (n < 4) throw MemoryAccessException("Not enough bytes for int");
    if (bigEndian) {
        return (static_cast<uint32_t>(buf[0]) << 24) |
               (static_cast<uint32_t>(buf[1]) << 16) |
               (static_cast<uint32_t>(buf[2]) << 8) |
                static_cast<uint32_t>(buf[3]);
    } else {
        return  static_cast<uint32_t>(buf[0]) |
               (static_cast<uint32_t>(buf[1]) << 8) |
               (static_cast<uint32_t>(buf[2]) << 16) |
               (static_cast<uint32_t>(buf[3]) << 24);
    }
}

uint64_t Memory::getLong(const Address& addr) {
    return getLong(addr, isBigEndian());
}

uint64_t Memory::getLong(const Address& addr, bool bigEndian) {
    uint8_t buf[8];
    int n = getBytes(addr, buf, 8);
    if (n < 8) throw MemoryAccessException("Not enough bytes for long");
    if (bigEndian) {
        return (static_cast<uint64_t>(buf[0]) << 56) |
               (static_cast<uint64_t>(buf[1]) << 48) |
               (static_cast<uint64_t>(buf[2]) << 40) |
               (static_cast<uint64_t>(buf[3]) << 32) |
               (static_cast<uint64_t>(buf[4]) << 24) |
               (static_cast<uint64_t>(buf[5]) << 16) |
               (static_cast<uint64_t>(buf[6]) << 8) |
                static_cast<uint64_t>(buf[7]);
    } else {
        return  static_cast<uint64_t>(buf[0]) |
               (static_cast<uint64_t>(buf[1]) << 8) |
               (static_cast<uint64_t>(buf[2]) << 16) |
               (static_cast<uint64_t>(buf[3]) << 24) |
               (static_cast<uint64_t>(buf[4]) << 32) |
               (static_cast<uint64_t>(buf[5]) << 40) |
               (static_cast<uint64_t>(buf[6]) << 48) |
               (static_cast<uint64_t>(buf[7]) << 56);
    }
}

void Memory::setShort(const Address& addr, uint16_t value) {
    setShort(addr, value, isBigEndian());
}

void Memory::setShort(const Address& addr, uint16_t value, bool bigEndian) {
    uint8_t buf[2];
    if (bigEndian) {
        buf[0] = static_cast<uint8_t>(value >> 8);
        buf[1] = static_cast<uint8_t>(value);
    } else {
        buf[0] = static_cast<uint8_t>(value);
        buf[1] = static_cast<uint8_t>(value >> 8);
    }
    setBytes(addr, buf, 2);
}

void Memory::setInt(const Address& addr, uint32_t value) {
    setInt(addr, value, isBigEndian());
}

void Memory::setInt(const Address& addr, uint32_t value, bool bigEndian) {
    uint8_t buf[4];
    if (bigEndian) {
        buf[0] = static_cast<uint8_t>(value >> 24);
        buf[1] = static_cast<uint8_t>(value >> 16);
        buf[2] = static_cast<uint8_t>(value >> 8);
        buf[3] = static_cast<uint8_t>(value);
    } else {
        buf[0] = static_cast<uint8_t>(value);
        buf[1] = static_cast<uint8_t>(value >> 8);
        buf[2] = static_cast<uint8_t>(value >> 16);
        buf[3] = static_cast<uint8_t>(value >> 24);
    }
    setBytes(addr, buf, 4);
}

void Memory::setLong(const Address& addr, uint64_t value) {
    setLong(addr, value, isBigEndian());
}

void Memory::setLong(const Address& addr, uint64_t value, bool bigEndian) {
    uint8_t buf[8];
    if (bigEndian) {
        buf[0] = static_cast<uint8_t>(value >> 56);
        buf[1] = static_cast<uint8_t>(value >> 48);
        buf[2] = static_cast<uint8_t>(value >> 40);
        buf[3] = static_cast<uint8_t>(value >> 32);
        buf[4] = static_cast<uint8_t>(value >> 24);
        buf[5] = static_cast<uint8_t>(value >> 16);
        buf[6] = static_cast<uint8_t>(value >> 8);
        buf[7] = static_cast<uint8_t>(value);
    } else {
        buf[0] = static_cast<uint8_t>(value);
        buf[1] = static_cast<uint8_t>(value >> 8);
        buf[2] = static_cast<uint8_t>(value >> 16);
        buf[3] = static_cast<uint8_t>(value >> 24);
        buf[4] = static_cast<uint8_t>(value >> 32);
        buf[5] = static_cast<uint8_t>(value >> 40);
        buf[6] = static_cast<uint8_t>(value >> 48);
        buf[7] = static_cast<uint8_t>(value >> 56);
    }
    setBytes(addr, buf, 8);
}

// DefaultMemoryBlock implementations

DefaultMemoryBlock::DefaultMemoryBlock(const std::string& name, const Address& start, long long size,
                                       bool initialized, uint8_t initialValue,
                                       bool overlay, bool loaded)
    : start_(start), 
      end_(start.getAddressSpace() ? start.add(size - 1) : Address(nullptr, start.getOffset() + size - 1)), 
      name_(name), flags_(FLAG_READ | FLAG_WRITE),
      initialized_(initialized), overlay_(overlay), loaded_(loaded) {
    if (initialized) {
        data_.resize(static_cast<size_t>(size), initialValue);
    }
}

const Address& DefaultMemoryBlock::getStart() const { return start_; }
const Address& DefaultMemoryBlock::getEnd() const { return end_; }

long long DefaultMemoryBlock::getSize() const {
    return end_.getOffset() - start_.getOffset() + 1;
}

std::string DefaultMemoryBlock::getName() const { return name_; }

void DefaultMemoryBlock::setName(const std::string& name) {
    if (!Memory::isValidMemoryBlockName(name)) {
        throw std::invalid_argument("Invalid memory block name");
    }
    name_ = name;
}

std::string DefaultMemoryBlock::getComment() const { return comment_; }
void DefaultMemoryBlock::setComment(const std::string& comment) { comment_ = comment; }

std::string DefaultMemoryBlock::getSourceName() const { return sourceName_; }
void DefaultMemoryBlock::setSourceName(const std::string& sourceName) { sourceName_ = sourceName; }

int DefaultMemoryBlock::getFlags() const { return flags_; }

void DefaultMemoryBlock::setRead(bool r) {
    if (r) flags_ |= FLAG_READ; else flags_ &= ~FLAG_READ;
}
void DefaultMemoryBlock::setWrite(bool w) {
    if (w) flags_ |= FLAG_WRITE; else flags_ &= ~FLAG_WRITE;
}
void DefaultMemoryBlock::setExecute(bool e) {
    if (e) flags_ |= FLAG_EXECUTE; else flags_ &= ~FLAG_EXECUTE;
}
void DefaultMemoryBlock::setVolatile(bool v) {
    if (v) flags_ |= FLAG_VOLATILE; else flags_ &= ~FLAG_VOLATILE;
}
void DefaultMemoryBlock::setArtificial(bool a) {
    if (a) flags_ |= FLAG_ARTIFICIAL; else flags_ &= ~FLAG_ARTIFICIAL;
}

MemoryBlockType DefaultMemoryBlock::getType() const { return MemoryBlockType::DEFAULT; }
bool DefaultMemoryBlock::isInitialized() const { return initialized_; }
bool DefaultMemoryBlock::isOverlay() const { return overlay_; }
bool DefaultMemoryBlock::isLoaded() const { return loaded_; }

uint8_t DefaultMemoryBlock::getByte(const Address& addr) const {
    if (!contains(addr)) {
        throw std::invalid_argument("Address is not in this block");
    }
    if (!initialized_) {
        throw MemoryAccessException("Block is uninitialized");
    }
    long long offset = addr.getOffset() - start_.getOffset();
    return data_[static_cast<size_t>(offset)];
}

int DefaultMemoryBlock::getBytes(const Address& addr, uint8_t* buf, int len) const {
    if (!contains(addr)) {
        throw std::invalid_argument("Address is not in this block");
    }
    if (!initialized_) {
        throw MemoryAccessException("Block is uninitialized");
    }
    long long offset = addr.getOffset() - start_.getOffset();
    long long available = static_cast<long long>(data_.size()) - offset;
    int toRead = static_cast<int>(std::min(static_cast<long long>(len), available));
    std::memcpy(buf, data_.data() + static_cast<size_t>(offset), static_cast<size_t>(toRead));
    return toRead;
}

void DefaultMemoryBlock::putByte(const Address& addr, uint8_t value) {
    if (!contains(addr)) {
        throw std::invalid_argument("Address is not in this block");
    }
    if (!isWrite()) {
        throw MemoryAccessException("Block is not writable");
    }
    long long offset = addr.getOffset() - start_.getOffset();
    data_[static_cast<size_t>(offset)] = value;
    initialized_ = true;
}

int DefaultMemoryBlock::putBytes(const Address& addr, const uint8_t* buf, int len) {
    if (!contains(addr)) {
        throw std::invalid_argument("Address is not in this block");
    }
    if (!isWrite()) {
        throw MemoryAccessException("Block is not writable");
    }
    long long offset = addr.getOffset() - start_.getOffset();
    long long available = static_cast<long long>(data_.size()) - offset;
    int toWrite = static_cast<int>(std::min(static_cast<long long>(len), available));
    std::memcpy(data_.data() + static_cast<size_t>(offset), buf, static_cast<size_t>(toWrite));
    initialized_ = true;
    return toWrite;
}

// DefaultMemory implementations

DefaultMemory::DefaultMemory(bool bigEndian) : bigEndian_(bigEndian) {}

bool DefaultMemory::isBigEndian() const { return bigEndian_; }

long long DefaultMemory::getSize() const {
    long long total = 0;
    for (const auto& block : blocks_) {
        total += block->getSize();
    }
    return total;
}

MemoryBlock* DefaultMemory::getBlock(const Address& addr) {
    int idx = findBlockIndex(addr);
    return (idx >= 0) ? blocks_[idx].get() : nullptr;
}

MemoryBlock* DefaultMemory::getBlock(const std::string& blockName) {
    for (const auto& block : blocks_) {
        if (block->getName() == blockName) return block.get();
    }
    return nullptr;
}

std::vector<MemoryBlock*> DefaultMemory::getBlocks() {
    std::vector<MemoryBlock*> result;
    for (const auto& block : blocks_) {
        result.push_back(block.get());
    }
    return result;
}

int DefaultMemory::findBlockIndex(const Address& addr) {
    if (lastFoundIndex_ >= 0 && lastFoundIndex_ < static_cast<int>(blocks_.size()) &&
        blocks_[lastFoundIndex_]->contains(addr)) {
        return lastFoundIndex_;
    }
    for (int i = 0; i < static_cast<int>(blocks_.size()); ++i) {
        if (blocks_[i]->contains(addr)) {
            lastFoundIndex_ = i;
            return i;
        }
    }
    return -1;
}

DefaultMemoryBlock* DefaultMemory::createInitializedBlock(const std::string& name, const Address& start,
                                                           long long size, bool overlay) {
    if (!isValidMemoryBlockName(name)) {
        throw std::invalid_argument("Invalid memory block name");
    }
    if (size <= 0) {
        throw std::invalid_argument("Block size must be positive");
    }
    auto block = std::make_unique<DefaultMemoryBlock>(name, start, size, true, 0, overlay);
    DefaultMemoryBlock* raw = block.get();
    blocks_.push_back(std::move(block));
    lastFoundIndex_ = -1;
    return raw;
}

DefaultMemoryBlock* DefaultMemory::createInitializedBlock(const std::string& name, const Address& start,
                                                           long long size, uint8_t initialValue,
                                                           bool overlay) {
    if (!isValidMemoryBlockName(name)) {
        throw std::invalid_argument("Invalid memory block name");
    }
    if (size <= 0) {
        throw std::invalid_argument("Block size must be positive");
    }
    auto block = std::make_unique<DefaultMemoryBlock>(name, start, size, true, initialValue, overlay);
    DefaultMemoryBlock* raw = block.get();
    blocks_.push_back(std::move(block));
    lastFoundIndex_ = -1;
    return raw;
}

DefaultMemoryBlock* DefaultMemory::createUninitializedBlock(const std::string& name, const Address& start,
                                                             long long size, bool overlay) {
    if (!isValidMemoryBlockName(name)) {
        throw std::invalid_argument("Invalid memory block name");
    }
    if (size <= 0) {
        throw std::invalid_argument("Block size must be positive");
    }
    auto block = std::make_unique<DefaultMemoryBlock>(name, start, size, false, 0, overlay);
    DefaultMemoryBlock* raw = block.get();
    blocks_.push_back(std::move(block));
    lastFoundIndex_ = -1;
    return raw;
}

bool DefaultMemory::removeBlock(MemoryBlock* block) {
    auto it = std::remove_if(blocks_.begin(), blocks_.end(),
        [block](const std::unique_ptr<DefaultMemoryBlock>& b) {
            return b.get() == block;
        });
    bool removed = (it != blocks_.end());
    blocks_.erase(it, blocks_.end());
    if (removed) lastFoundIndex_ = -1;
    return removed;
}

bool DefaultMemory::removeBlock(const std::string& name) {
    auto it = std::remove_if(blocks_.begin(), blocks_.end(),
        [&name](const std::unique_ptr<DefaultMemoryBlock>& b) {
            return b->getName() == name;
        });
    bool removed = (it != blocks_.end());
    blocks_.erase(it, blocks_.end());
    if (removed) lastFoundIndex_ = -1;
    return removed;
}

} // namespace ghidra
