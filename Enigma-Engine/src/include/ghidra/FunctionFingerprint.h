/* ###
 * IP: GHIDRA
 *
 * Function fingerprint for FKS — multi-hash representation of a function.
 */
#pragma once

#include <cstdint>

namespace ghidra {

class Function;
class Program;

// V1 fingerprint: raw-byte FNV-1a hashing (backward-compatible with FidHasher).
struct FingerprintV1 {
    uint64_t fullHash  = 0;  // Primary key — masked instruction bytes
    uint64_t shortHash = 0;  // First 32 raw bytes (FLIRT-compatible)
    uint64_t mnemHash  = 0;  // Mnemonic sequence only (compiler-neutral)
    uint64_t callHash  = 0;  // Full hash with call targets zeroed

    bool operator==(const FingerprintV1& o) const {
        return fullHash == o.fullHash && shortHash == o.shortHash
            && mnemHash == o.mnemHash && callHash == o.callHash;
    }
    bool hasHashes() const { return fullHash != 0 || shortHash != 0; }
};

// V2 fingerprint: Capstone instruction-aware hashing (cross-binary stable).
struct FingerprintV2 {
    uint64_t fullHash  = 0;  // Mnemonic opcode sequence hash (MOV,PUSH,SUB,...)
    uint64_t shortHash = 0;  // First 8 mnemonics hash (quick prefix filter)
    uint64_t mnemHash  = 0;  // Mnemonic sequence with calls/jumps excluded
    uint64_t callHash  = 0;  // First 4 bytes of each instruction hashed

    bool operator==(const FingerprintV2& o) const {
        return fullHash == o.fullHash && shortHash == o.shortHash
            && mnemHash == o.mnemHash && callHash == o.callHash;
    }
    bool hasHashes() const { return fullHash != 0 || shortHash != 0; }
};

// Combined fingerprint: V1 (raw bytes) + V2 (instruction-aware).
struct FunctionFingerprint {
    FingerprintV1 v1;
    FingerprintV2 v2;

    bool operator==(const FunctionFingerprint& o) const {
        return v1 == o.v1 && v2 == o.v2;
    }
    bool hasHashes() const { return v1.hasHashes() || v2.hasHashes(); }

    // Backward-compatible accessors for V1 hashes.
    uint64_t fullHash()  const { return v1.fullHash; }
    uint64_t shortHash() const { return v1.shortHash; }
    uint64_t mnemHash()  const { return v1.mnemHash; }
    uint64_t callHash()  const { return v1.callHash; }
};

// Computes a 4-hash fingerprint for a function.
// Phase 1: raw-byte hashing (backward-compatible with FidHasher).
// Phase 2: Capstone instruction-aware hashing.
class FunctionFingerprinter {
public:
    static constexpr int MAX_SHORT_HASH_BYTES = 32;

    FunctionFingerprint compute(Function* func, Program* program);
};

} // namespace ghidra
