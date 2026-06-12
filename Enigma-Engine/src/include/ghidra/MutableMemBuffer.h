#pragma once

#include <ghidra/MemBuffer.h>
#include <ghidra/AddressOverflowException.h>

namespace ghidra {

class MutableMemBuffer : public MemBuffer {
public:
    ~MutableMemBuffer() override = default;

    virtual void advance(int displacement) = 0;
    virtual void setPosition(const Address& addr) = 0;
    virtual MutableMemBuffer* clone() const = 0;
};

} // namespace ghidra
