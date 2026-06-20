#include <ghidra/KnownFunctionHashes.h>
#include <cstring>

namespace ghidra {

KnownFunctionHashes::KnownFunctionHashes() {
    // Populated from bootstrapping against reference binaries.
    // Hashes are FNV-1a 64-bit of first 32 raw instruction bytes at function entry.
    // Only exact matches are used; function length is NOT checked (allows
    // matching regardless of function body boundary determination).

    // MSVC CFG guard stubs (bootstrapped from notepad_test.exe)
    add(0x719f5cfffe5826acULL, "_guard_check_icall");
    add(0x9408b804ccaebdcaULL, "_guard_dispatch_icall");

    // __security_check_cookie pattern (first 3 bytes: 48 33 0d = xor [rip+...])
    add(0x891c08d0f2875233ULL, "__security_check_cookie");

    // Common short library stubs (bootstrapped patterns)
    // __chkstk: sub rsp, ...
    // (add more as identified)

    // Entry point recognition
    add(0x4b1f572b94053afdULL, "entry");
}

void KnownFunctionHashes::add(uint64_t hash, const char* name) {
    if (entryCount_ >= MAX_ENTRIES) return;
    entries_[entryCount_] = {hash, 0, name};
    hashMap_[hash] = name;
    ++entryCount_;
}

const char* KnownFunctionHashes::lookup(uint64_t fullHash, int totalBytes) const {
    auto it = hashMap_.find(fullHash);
    if (it != hashMap_.end()) {
        return it->second;
    }
    return nullptr;
}

} // namespace ghidra
