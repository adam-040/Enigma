#pragma once

#include <ghidra/ByteProvider.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class BinaryReader {
public:
    BinaryReader(ByteProvider* provider, bool isBigEndian);
    BinaryReader(std::unique_ptr<ByteProvider> provider, bool isBigEndian);

    uint8_t readByte(uint64_t offset) const;
    int16_t readShort(uint64_t offset) const;
    int32_t readInt(uint64_t offset) const;
    int64_t readLong(uint64_t offset) const;

    uint16_t readUnsignedShort(uint64_t offset) const;
    uint32_t readUnsignedInt(uint64_t offset) const;
    uint64_t readUnsignedLong(uint64_t offset) const;

    std::string readAsciiString(uint64_t offset, int length) const;
    std::string readUnicodeString(uint64_t offset, int length) const;

    int readByteArray(uint64_t offset, uint8_t* buf, int size) const;
    std::vector<uint8_t> readByteArray(uint64_t offset, int size) const;

    uint64_t length() const;
    bool isBigEndian() const { return isBigEndian_; }
    ByteProvider* getByteProvider() const { return provider_; }

private:
    ByteProvider* provider_;
    bool ownsProvider_;
    std::unique_ptr<ByteProvider> ownedProvider_;
    bool isBigEndian_;
};

} // namespace ghidra
