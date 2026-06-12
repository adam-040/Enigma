#include <ghidra/DumbMemBufferImpl.h>

namespace ghidra {

DumbMemBufferImpl::DumbMemBufferImpl(Memory* mem, const Address& addr)
    : MemoryBufferImpl(mem, addr, BUF_SIZE) {
}

} // namespace ghidra
