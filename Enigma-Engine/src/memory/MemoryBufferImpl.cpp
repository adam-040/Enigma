#include <ghidra/MemoryBufferImpl.h>
#include <ghidra/MemBufferInputStream.h>
#include <ghidra/AddressOverflowException.h>
#include <ghidra/AddressOutOfBoundsException.h>
#include <algorithm>

namespace ghidra {

MemoryBufferImpl::MemoryBufferImpl(Memory* mem, const Address& addr)
    : mem_(mem), startAddr_(addr), converter_(GhidraDataConverter::getConverter(mem->isBigEndian())) {
    buffer_.resize(DEFAULT_BUFSIZE);
    threshold_ = DEFAULT_BUFSIZE / 100;
    setPosition(addr);
}

MemoryBufferImpl::MemoryBufferImpl(Memory* mem, const Address& addr, int bufSize)
    : mem_(mem), startAddr_(addr), converter_(GhidraDataConverter::getConverter(mem->isBigEndian())) {
    buffer_.resize(bufSize);
    threshold_ = bufSize / 100;
    setPosition(addr);
}

MemoryBufferImpl* MemoryBufferImpl::clone() const {
    return new MemoryBufferImpl(mem_, startAddr_, static_cast<int>(buffer_.size()));
}

void MemoryBufferImpl::advance(int displacement) {
    Address addr = startAddr_.addNoWrap(displacement);
    setPosition(addr);
}

void MemoryBufferImpl::setPosition(const Address& addr) {
    if (minOffset_ <= maxOffset_) {
        if (*addr.getAddressSpace() == *startAddr_.getAddressSpace()) {
            int64_t diff = addr.subtract(startAddr_);
            if (diff >= minOffset_ && diff < maxOffset_ - threshold_) {
                startAddr_ = addr;
                minOffset_ -= static_cast<int>(diff);
                maxOffset_ -= static_cast<int>(diff);
                startAddrIndex_ += static_cast<int>(diff);
                return;
            }
        }
    }
    startAddr_ = addr;
    startAddrIndex_ = 0;
    minOffset_ = 0;
    maxOffset_ = -1;

    try {
        int nRead = mem_->getBytes(addr, buffer_.data(), static_cast<int>(buffer_.size()));
        maxOffset_ = nRead - 1;
    } catch (const AddressOutOfBoundsException&) {
    } catch (const MemoryAccessException&) {
    }
}

int8_t MemoryBufferImpl::getByte(int offset) const {
    if (offset >= minOffset_ && offset <= maxOffset_) {
        return static_cast<int8_t>(buffer_[static_cast<size_t>(startAddrIndex_ + offset)]);
    }
    try {
        Address addr = startAddr_.addNoWrap(offset);
        auto* self = const_cast<MemoryBufferImpl*>(this);
        int nRead = mem_->getBytes(addr, self->buffer_.data(), static_cast<int>(self->buffer_.size()));

        self->startAddrIndex_ = -offset;
        self->minOffset_ = offset;
        self->maxOffset_ = offset + nRead - 1;

        return static_cast<int8_t>(self->buffer_[0]);
    } catch (const AddressOverflowException& e) {
        throw MemoryAccessException(e.what());
    }
}

int MemoryBufferImpl::getBytes(std::vector<uint8_t>& b, int offset) const {
    int n = static_cast<int>(b.size());
    return getBytes(b.data(), n, offset);
}

int MemoryBufferImpl::getBytes(uint8_t* b, int length, int offset) const {
    int bufOff = startAddrIndex_ + offset;
    if (offset >= minOffset_ && (offset + length) <= maxOffset_) {
        std::copy(buffer_.begin() + bufOff, buffer_.begin() + bufOff + length, b);
        return length;
    }
    try {
        return mem_->getBytes(startAddr_.addNoWrap(offset), b, length);
    } catch (...) {
        return 0;
    }
}

Address MemoryBufferImpl::getAddress() const {
    return startAddr_;
}

Memory* MemoryBufferImpl::getMemory() const {
    return mem_;
}

bool MemoryBufferImpl::isBigEndian() const {
    return mem_->isBigEndian();
}

int16_t MemoryBufferImpl::getShort(int offset) const {
    return converter_->getShort(this, offset);
}

int32_t MemoryBufferImpl::getInt(int offset) const {
    return converter_->getInt(this, offset);
}

int64_t MemoryBufferImpl::getLong(int offset) const {
    return converter_->getLong(this, offset);
}

std::vector<uint8_t> MemoryBufferImpl::getBigInteger(int offset, int size, bool signed_val) const {
    return converter_->getBigInteger(this, offset, size, signed_val);
}

std::unique_ptr<std::istream> MemoryBufferImpl::getInputStream() const {
    return std::make_unique<MemBufferInputStream>(this, 0, 0);
}

std::unique_ptr<std::istream> MemoryBufferImpl::getInputStream(int initialPosition, int length) const {
    return std::make_unique<MemBufferInputStream>(this, initialPosition, length);
}

} // namespace ghidra
