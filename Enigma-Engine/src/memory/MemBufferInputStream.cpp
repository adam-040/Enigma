#include <ghidra/MemBufferInputStream.h>
#include <ghidra/MemoryAccessException.h>

namespace ghidra {

MemBufferStreamBuf::MemBufferStreamBuf(const MemBuffer* buf, int initialPosition, int length)
    : buf_(buf), position_(initialPosition), maxPosition_(length > 0 ? initialPosition + length : 0),
      currentByte_(0) {
    if (length <= 0 && buf) {
        maxPosition_ = 0;
    }
}

MemBufferStreamBuf::int_type MemBufferStreamBuf::underflow() {
    if (!buf_) {
        return traits_type::eof();
    }
    if (maxPosition_ > 0 && position_ >= maxPosition_) {
        return traits_type::eof();
    }
    try {
        currentByte_ = static_cast<uint8_t>(buf_->getByte(position_));
        setg(reinterpret_cast<char*>(&currentByte_),
             reinterpret_cast<char*>(&currentByte_),
             reinterpret_cast<char*>(&currentByte_) + 1);
        position_++;
        return traits_type::to_int_type(currentByte_);
    } catch (const MemoryAccessException&) {
        return traits_type::eof();
    }
}

MemBufferInputStream::MemBufferInputStream(const MemBuffer* buf, int initialPosition, int length)
    : std::istream(&streamBuf_), streamBuf_(buf, initialPosition, length) {
}

int MemBufferInputStream::available() const {
    if (streamBuf_.maxPosition_ > 0) {
        int remaining = streamBuf_.maxPosition_ - streamBuf_.position_;
        return (remaining > 0) ? remaining : 0;
    }
    return 0;
}

void MemBufferInputStream::close() {
    const_cast<MemBufferStreamBuf&>(streamBuf_).maxPosition_ = 0;
}

int MemBufferInputStream::read() {
    int_type c = streamBuf_.sbumpc();
    if (c == traits_type::eof()) {
        return -1;
    }
    return c;
}

} // namespace ghidra
