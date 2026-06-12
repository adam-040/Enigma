#pragma once

#include <ghidra/MemBuffer.h>
#include <ghidra/Address.h>
#include <ghidra/MemoryAccessException.h>
#include <ghidra/AddressOutOfBoundsException.h>
#include <ghidra/GhidraDataConverter.h>
#include <cstdint>
#include <vector>
#include <memory>

namespace ghidra {

class WrappedMemBuffer : public MemBuffer {
public:
    static constexpr int DEFAULT_BUFSIZE = 0;

    WrappedMemBuffer(const MemBuffer* buf, int baseOffset);
    WrappedMemBuffer(const MemBuffer* buf, int bufferSize, int baseOffset);

    int8_t getByte(int offset) const override;
    int getBytes(std::vector<uint8_t>& b, int offset) const override;
    int getBytes(uint8_t* b, int length, int offset) const override;
    Address getAddress() const override;
    Memory* getMemory() const override;
    bool isBigEndian() const override;

    int16_t getShort(int offset) const override;
    int32_t getInt(int offset) const override;
    int64_t getLong(int offset) const override;
    std::vector<uint8_t> getBigInteger(int offset, int size, bool signed_val) const override;

    std::unique_ptr<std::istream> getInputStream() const override;
    std::unique_ptr<std::istream> getInputStream(int initialPosition, int length) const override;

private:
    void setBaseOffset(int offset);
    int computeOffset(int offset) const;
    void fillBuffer(int offset);

    const MemBuffer* memBuffer_;
    int baseOffset_;
    Address address_;
    const GhidraDataConverter* converter_;
    std::vector<uint8_t> buffer_;
    mutable int minOffset_ = 0;
    mutable int maxOffset_ = -1;
};

} // namespace ghidra
