#pragma once
#include <cstdint>
#include <unordered_map>

namespace ghidra {

struct KnownFunctionEntry {
    uint64_t fullHash;
    int totalBytes;
    const char* name;
};

class KnownFunctionHashes {
public:
    KnownFunctionHashes();

    const char* lookup(uint64_t fullHash, int totalBytes) const;

private:
    static constexpr int MAX_ENTRIES = 256;
    KnownFunctionEntry entries_[MAX_ENTRIES];
    int entryCount_ = 0;
    std::unordered_map<uint64_t, const char*> hashMap_;

    void add(uint64_t hash, const char* name);
};

} // namespace ghidra
