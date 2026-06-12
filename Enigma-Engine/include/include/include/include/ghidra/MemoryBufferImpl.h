#pragma once

#include <ghidra/MutableMemBuffer.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/MemoryAccessException.h>
#include <ghidra/GhidraDataConverter.h>
#include <cstdint>
#include <vector>

namespace ghidra {

class MemoryBufferImpl : public MutableMemBuffer {
public:
    static constexpr int DEFAULT_BUFSIZE = 1024;

    MemoryBufferImpl(Memory* mem, const Address& addr);
    MemoryBufferImpl(Memory* mem, const Address& addr, int bufSize);

    MemoryBufferImpl* clone() const override;

    void advance(int displacement) override;
    void setPosition(const Address& addr) override;

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

protected:
    Memory* mem_;
    Address startAddr_;
    std::vector<uint8_t> buffer_;
    int startAddrIndex_ = 0;
    int minOffset_ = 0;
    int maxOffset_ = -1;
    int threshold_ = 0;
    const GhidraDataConverter* converter_;
};

} // namespace ghidra
