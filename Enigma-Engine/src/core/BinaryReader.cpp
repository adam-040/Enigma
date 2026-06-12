#include <ghidra/BinaryReader.h>
#include <algorithm>
#include <cstring>

namespace ghidra {

BinaryReader::BinaryReader(ByteProvider* provider, bool isBigEndian)
    : provider_(provider), ownsProvider_(false), isBigEndian_(isBigEndian) {
}

BinaryReader::BinaryReader(std::unique_ptr<ByteProvider> provider, bool isBigEndian)
    : provider_(provider.get()), ownsProvider_(true),
      ownedProvider_(std::move(provider)), isBigEndian_(isBigEndian) {
}

uint8_t BinaryReader::readByte(uint64_t offset) const {
    return provider_->readByte(offset);
}

int16_t BinaryReader::readShort(uint64_t offset) const {
    uint8_t bytes[2];
    provider_->readBytes(offset, bytes, 2);
    if (isBigEndian_) {
        return static_cast<int16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
    }
    return static_cast<int16_t>((static_cast<uint16_t>(bytes[1]) << 8) | bytes[0]);
}

int32_t BinaryReader::readInt(uint64_t offset) const {
    uint8_t bytes[4];
    provider_->readBytes(offset, bytes, 4);
    if (isBigEndian_) {
        return (static_cast<int32_t>(bytes[0]) << 24) |
               (static_cast<int32_t>(bytes[1]) << 16) |
               (static_cast<int32_t>(bytes[2]) << 8)  |
               bytes[3];
    }
    return (static_cast<int32_t>(bytes[3]) << 24) |
           (static_cast<int32_t>(bytes[2]) << 16) |
           (static_cast<int32_t>(bytes[1]) << 8)  |
           bytes[0];
}

int64_t BinaryReader::readLong(uint64_t offset) const {
    uint8_t bytes[8];
    provider_->readBytes(offset, bytes, 8);
    if (isBigEndian_) {
        return (static_cast<int64_t>(bytes[0]) << 56) |
               (static_cast<int64_t>(bytes[1]) << 48) |
               (static_cast<int64_t>(bytes[2]) << 40) |
               (static_cast<int64_t>(bytes[3]) << 32) |
               (static_cast<int64_t>(bytes[4]) << 24) |
               (static_cast<int64_t>(bytes[5]) << 16) |
               (static_cast<int64_t>(bytes[6]) << 8)  |
               static_cast<int64_t>(bytes[7]);
    }
    return (static_cast<int64_t>(bytes[7]) << 56) |
           (static_cast<int64_t>(bytes[6]) << 48) |
           (static_cast<int64_t>(bytes[5]) << 40) |
           (static_cast<int64_t>(bytes[4]) << 32) |
           (static_cast<int64_t>(bytes[3]) << 24) |
           (static_cast<int64_t>(bytes[2]) << 16) |
           (static_cast<int64_t>(bytes[1]) << 8)  |
           static_cast<int64_t>(bytes[0]);
}

uint16_t BinaryReader::readUnsignedShort(uint64_t offset) const {
    return static_cast<uint16_t>(readShort(offset));
}

uint32_t BinaryReader::readUnsignedInt(uint64_t offset) const {
    return static_cast<uint32_t>(readInt(offset));
}

uint64_t BinaryReader::readUnsignedLong(uint64_t offset) const {
    return static_cast<uint64_t>(readLong(offset));
}

std::string BinaryReader::readAsciiString(uint64_t offset, int length) const {
    std::vector<uint8_t> bytes(length + 1, 0);
    int n = provider_->readBytes(offset, bytes.data(), length);
    if (n < 0) return {};
    bytes[n] = 0;
    return std::string(reinterpret_cast<char*>(bytes.data()));
}

std::string BinaryReader::readUnicodeString(uint64_t offset, int length) const {
    std::vector<uint16_t> chars(length + 1, 0);
    for (int i = 0; i < length; i++) {
        chars[i] = readUnsignedShort(offset + i * 2);
    }
    chars[length] = 0;
    std::string result;
    for (int i = 0; i < length && chars[i] != 0; i++) {
        if (chars[i] <= 0x7F) {
            result += static_cast<char>(chars[i]);
        } else {
            result += '?';
        }
    }
    return result;
}

int BinaryReader::readByteArray(uint64_t offset, uint8_t* buf, int size) const {
    return provider_->readBytes(offset, buf, size);
}

std::vector<uint8_t> BinaryReader::readByteArray(uint64_t offset, int size) const {
    std::vector<uint8_t> result(size);
    int n = provider_->readBytes(offset, result.data(), size);
    if (n < 0) result.clear();
    return result;
}

uint64_t BinaryReader::length() const {
    return provider_->length();
}

} // namespace ghidra
