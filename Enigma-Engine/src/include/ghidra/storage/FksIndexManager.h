/* ###
 * IP: GHIDRA
 *
 * FksIndexManager — LMDB index for FKS hash lookups.
 * Mirrors the IndexManager pattern (key prefixes + LE uint64 keys).
 */
#pragma once

#include <ghidra/FksLibrary.h>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace ghidra {
namespace storage {

// Parsed candidate from an FkCandidateList.
struct CandidateInfo {
    uint64_t uid;
    std::string name;
    std::string nameDemangled;
    std::string namespacePath;
    std::string signature;
    std::string family;
    std::string compiler;
    uint32_t bodySize;
    uint16_t instrCount;
};

class FksIndexManager {
public:
    // LMDB key prefixes for V1 hashes (0x10–0x13)
    static constexpr uint8_t PREFIX_FULL_HASH  = 0x10;
    static constexpr uint8_t PREFIX_SHORT_HASH = 0x11;
    static constexpr uint8_t PREFIX_MNEM_HASH  = 0x12;
    static constexpr uint8_t PREFIX_CALL_HASH  = 0x13;

    // LMDB key prefixes for V2 hashes (0x20–0x23)
    static constexpr uint8_t PREFIX_FULL_HASH_V2  = 0x20;
    static constexpr uint8_t PREFIX_SHORT_HASH_V2 = 0x21;
    static constexpr uint8_t PREFIX_MNEM_HASH_V2  = 0x22;
    static constexpr uint8_t PREFIX_CALL_HASH_V2  = 0x23;

    // LMDB key prefix for address-based lookup (0x30)
    static constexpr uint8_t PREFIX_ADDRESS = 0x30;

    // LMDB key prefix for demangled name hash (0x40)
    static constexpr uint8_t PREFIX_DEMANGLED_NAME = 0x40;

    // LMDB key prefix for namespace path hash (0x41)
    static constexpr uint8_t PREFIX_NAMESPACE = 0x41;

    // LMDB key prefix for body-size + instr-count composite (0x50)
    static constexpr uint8_t PREFIX_BODY_INSTR = 0x50;

    static int rebuildFromFksDir(const std::string& fksDir);
    static bool indexLibrary(const std::string& fksDir, const FksLibrary& lib);

    // V1 lookups
    static std::vector<uint8_t> lookupByHash(const std::string& fksDir,
                                             uint8_t prefix, uint64_t hash);
    static std::vector<uint8_t> lookupByFullHash(const std::string& fksDir, uint64_t hash);
    static std::vector<uint8_t> lookupByShortHash(const std::string& fksDir, uint64_t hash);
    static std::vector<uint8_t> lookupByMnemHash(const std::string& fksDir, uint64_t hash);
    static std::vector<uint8_t> lookupByCallHash(const std::string& fksDir, uint64_t hash);

    // V2 lookups
    static std::vector<uint8_t> lookupByFullHashV2(const std::string& fksDir, uint64_t hash);
    static std::vector<uint8_t> lookupByShortHashV2(const std::string& fksDir, uint64_t hash);
    static std::vector<uint8_t> lookupByMnemHashV2(const std::string& fksDir, uint64_t hash);
    static std::vector<uint8_t> lookupByCallHashV2(const std::string& fksDir, uint64_t hash);

    // Address-based lookup
    static std::vector<uint8_t> lookupByAddress(const std::string& fksDir, const std::string& family, uint64_t address);

    // Name-based lookups
    static std::vector<uint8_t> lookupByDemangledName(const std::string& fksDir, uint64_t nameHash);
    static std::vector<uint8_t> lookupByNamespace(const std::string& fksDir, uint64_t nsHash);

    // Composite key lookup (body_size + instr_count)
    static std::vector<uint8_t> lookupByBodyInstr(const std::string& fksDir, uint64_t compositeKey);

    // Parse all candidates from raw FkCandidateList bytes
    static std::vector<CandidateInfo> extractAllCandidates(const std::vector<uint8_t>& data);

    // Build a per-UID callee set index from all .fkslib files.
    // Returns map: uid → sorted vector of callee UIDs
    static std::unordered_map<uint64_t, std::vector<uint64_t>> buildCalleeIndex(const std::string& fksDir);

    // Score a candidate against a local callee set by counting overlapping callees.
    static int scoreCandidateByCallees(
        const CandidateInfo& candidate,
        const std::unordered_map<uint64_t, std::vector<uint64_t>>& calleeIndex,
        const std::vector<uint64_t>& localCallees);

    static bool indexExists(const std::string& fksDir);
    static bool clear(const std::string& fksDir);
};

} // namespace storage
} // namespace ghidra
