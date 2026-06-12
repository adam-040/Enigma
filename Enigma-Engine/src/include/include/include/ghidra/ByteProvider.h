#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace ghidra {

class ByteProvider {
public:
    virtual ~ByteProvider() = default;
    virtual uint8_t readByte(uint64_t offset) const = 0;
    virtual int readBytes(uint64_t offset, uint8_t* buf, int size) const = 0;
    virtual uint64_t length() const = 0;
    virtual bool isBigEndian() const = 0;
    virtual std::string getName() const = 0;
};

} // namespace ghidra
