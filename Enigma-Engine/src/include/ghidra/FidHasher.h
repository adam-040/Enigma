#pragma once
#include <ghidra/FNV1a64.h>
#include <cstdint>

namespace ghidra {

class Function;
class Program;

struct FidHashQuad {
    uint64_t fullHash;
    int totalBytes;
};

class FidHasher {
public:
    static constexpr int MAX_HASH_BYTES = 32;

    FidHashQuad hashFunction(Function* func, Program* program);

private:
    uint64_t computeHash(const uint8_t* bytes, int length);
};

} // namespace ghidra
