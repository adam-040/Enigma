#pragma once

#include <ghidra/ByteProvider.h>
#include <ghidra/Address.h>

namespace ghidra {

class Memory;
class Program;

class MemoryByteProvider : public ByteProvider {
public:
    MemoryByteProvider(Memory* memory, const Address& baseAddress, Program* program = nullptr);

    uint8_t readByte(uint64_t offset) const override;
    int readBytes(uint64_t offset, uint8_t* buf, int size) const override;
    uint64_t length() const override;
    bool isBigEndian() const override;
    std::string getName() const override;

    Memory* getMemory() const { return memory_; }
    const Address& getBaseAddress() const { return baseAddress_; }

private:
    Memory* memory_;
    Address baseAddress_;
    Program* program_;
};

} // namespace ghidra
