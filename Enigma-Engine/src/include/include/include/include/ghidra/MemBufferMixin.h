#pragma once

#include <ghidra/MemBuffer.h>
#include <ghidra/MemoryAccessException.h>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace ghidra {

class MemBufferMixin : public MemBuffer {
public:
    ~MemBufferMixin() override = default;

    virtual int getBytes(std::vector<uint8_t>& buffer, int addressOffset) = 0;

    int8_t getByte(int offset) const override {
        std::vector<uint8_t> buf(1);
        if (getBytes(buf, offset) < 1) {
            throw MemoryAccessException("Couldn't get requested byte");
        }
        return static_cast<int8_t>(buf[0]);
    }

    int getBytes(uint8_t* b, int length, int offset) const override {
        std::vector<uint8_t> buf(b, b + length);
        int n = const_cast<MemBufferMixin*>(this)->getBytes(buf, offset);
        if (n > 0) {
            std::copy(buf.begin(), buf.begin() + n, b);
        }
        return n;
    }

    std::vector<uint8_t> getBytesInFull(int offset, int len) {
        std::vector<uint8_t> buf(len);
        if (getBytes(buf, offset) != len) {
            throw MemoryAccessException("Could not read enough bytes");
        }
        return buf;
    }

    int16_t getShort(int offset) const override {
        auto buf = const_cast<MemBufferMixin*>(this)->getBytesInFull(offset, 2);
        if (isBigEndian()) {
            return static_cast<int16_t>((buf[0] << 8) | buf[1]);
        }
        return static_cast<int16_t>(buf[0] | (buf[1] << 8));
    }

    int32_t getInt(int offset) const override {
        auto buf = const_cast<MemBufferMixin*>(this)->getBytesInFull(offset, 4);
        if (isBigEndian()) {
            return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        }
        return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
    }

    int64_t getLong(int offset) const override {
        auto buf = const_cast<MemBufferMixin*>(this)->getBytesInFull(offset, 8);
        int64_t result = 0;
        if (isBigEndian()) {
            for (int i = 0; i < 8; i++) {
                result = (result << 8) | buf[i];
            }
        } else {
            for (int i = 7; i >= 0; i--) {
                result = (result << 8) | buf[i];
            }
        }
        return result;
    }

    std::vector<uint8_t> getBigInteger(int offset, int size, bool signed_val) const override {
        auto buf = const_cast<MemBufferMixin*>(this)->getBytesInFull(offset, size);
        if (!isBigEndian()) {
            std::reverse(buf.begin(), buf.end());
        }
        return buf;
    }

    std::unique_ptr<std::istream> getInputStream() const override {
        return nullptr;
    }

    std::unique_ptr<std::istream> getInputStream(int initialPosition, int length) const override {
        return nullptr;
    }
};

} // namespace ghidra
