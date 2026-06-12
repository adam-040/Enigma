#pragma once

#include <ghidra/MemoryBufferImpl.h>

namespace ghidra {

class DumbMemBufferImpl : public MemoryBufferImpl {
public:
    static constexpr int BUF_SIZE = 16;

    DumbMemBufferImpl(Memory* mem, const Address& addr);
};

} // namespace ghidra
