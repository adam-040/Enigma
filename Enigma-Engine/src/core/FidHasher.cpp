#include <ghidra/FidHasher.h>
#include <ghidra/Function.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <cstring>

namespace ghidra {

FidHashQuad FidHasher::hashFunction(Function* func, Program* program) {
    FidHashQuad result{0, 0};
    if (!func || !program) return result;

    Memory* memory = program->getMemory();
    if (!memory) return result;

    Address entry = func->getEntryPoint();
    if (!entry.isValid()) return result;

    // Read the first MAX_HASH_BYTES of the function
    uint8_t buf[MAX_HASH_BYTES];
    int bytesRead = memory->getBytes(entry, buf, MAX_HASH_BYTES);
    if (bytesRead < 1) return result;

    result.totalBytes = bytesRead;

    // Compute FNV-1a hash of the raw bytes
    FNV1a64 hasher;
    hasher.update(buf, bytesRead);
    result.fullHash = hasher.digest();

    return result;
}

} // namespace ghidra
