#include <ghidra/WrappedMemBuffer.h>
#include <ghidra/MemBufferInputStream.h>
#include <algorithm>

namespace ghidra {

WrappedMemBuffer::WrappedMemBuffer(const MemBuffer* buf, int baseOffset)
    : WrappedMemBuffer(buf, DEFAULT_BUFSIZE, baseOffset) {
}

WrappedMemBuffer::WrappedMemBuffer(const MemBuffer* buf, int bufferSize, int baseOffset)
    : memBuffer_(buf), converter_(GhidraDataConverter::getConverter(buf->isBigEndian())) {
    buffer_.resize(bufferSize);
    setBaseOffset(baseOffset);
}

void WrappedMemBuffer::setBaseOffset(int offset) {
    address_ = memBuffer_->getAddress().add(offset);
    baseOffset_ = offset;

    if (!buffer_.empty()) {
        minOffset_ = 0;
        maxOffset_ = -1;
        maxOffset_ = memBuffer_->getBytes(buffer_, baseOffset_) - 1;
    }
}

int WrappedMemBuffer::computeOffset(int offset) const {
    int bufOffset = baseOffset_ + offset;
    if (offset > 0 && bufOffset < baseOffset_) {
        throw MemoryAccessException("Invalid WrappedMemBuffer, offset would wrap");
    }
    if (offset < 0 && bufOffset > baseOffset_) {
        throw MemoryAccessException("Invalid WrappedMemBuffer offset, offset would wrap");
    }
    return bufOffset;
}

int8_t WrappedMemBuffer::getByte(int offset) const {
    if (buffer_.empty()) {
        return memBuffer_->getByte(computeOffset(offset));
    }
    if (offset >= minOffset_ && offset <= maxOffset_) {
        return static_cast<int8_t>(buffer_[static_cast<size_t>(offset - minOffset_)]);
    }
    auto* self = const_cast<WrappedMemBuffer*>(this);
    self->fillBuffer(offset);
    return static_cast<int8_t>(self->buffer_[0]);
}

int WrappedMemBuffer::getBytes(std::vector<uint8_t>& b, int offset) const {
    int n = static_cast<int>(b.size());
    return getBytes(b.data(), n, offset);
}

int WrappedMemBuffer::getBytes(uint8_t* b, int length, int offset) const {
    try {
        if (buffer_.size() > 0 && length <= static_cast<int>(buffer_.size())) {
            if (offset < minOffset_ || (length + offset - 1) > maxOffset_) {
                auto* self = const_cast<WrappedMemBuffer*>(this);
                self->fillBuffer(offset);
            }
            if (offset >= minOffset_ && (length + offset - 1) <= maxOffset_) {
                std::copy(buffer_.begin() + (offset - minOffset_),
                          buffer_.begin() + (offset - minOffset_) + length, b);
                return length;
            }
        }
        return memBuffer_->getBytes(b, length, computeOffset(offset));
    } catch (const MemoryAccessException&) {
        return 0;
    }
}

void WrappedMemBuffer::fillBuffer(int offset) {
    int nRead = memBuffer_->getBytes(buffer_, computeOffset(offset));
    if (nRead == 0) {
        throw MemoryAccessException("No bytes available in memory to cache");
    }
    minOffset_ = offset;
    maxOffset_ = offset + nRead - 1;
}

Address WrappedMemBuffer::getAddress() const {
    return address_;
}

Memory* WrappedMemBuffer::getMemory() const {
    return memBuffer_->getMemory();
}

bool WrappedMemBuffer::isBigEndian() const {
    return memBuffer_->isBigEndian();
}

int16_t WrappedMemBuffer::getShort(int offset) const {
    return converter_->getShort(this, offset);
}

int32_t WrappedMemBuffer::getInt(int offset) const {
    return converter_->getInt(this, offset);
}

int64_t WrappedMemBuffer::getLong(int offset) const {
    return converter_->getLong(this, offset);
}

std::vector<uint8_t> WrappedMemBuffer::getBigInteger(int offset, int size, bool signed_val) const {
    return converter_->getBigInteger(this, offset, size, signed_val);
}

std::unique_ptr<std::istream> WrappedMemBuffer::getInputStream() const {
    return std::make_unique<MemBufferInputStream>(this, 0, 0);
}

std::unique_ptr<std::istream> WrappedMemBuffer::getInputStream(int initialPosition, int length) const {
    return std::make_unique<MemBufferInputStream>(this, initialPosition, length);
}

} // namespace ghidra
