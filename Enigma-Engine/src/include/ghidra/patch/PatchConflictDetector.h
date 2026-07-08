#pragma once

#include <vector>
#include <cstdint>

namespace ghidra::patch {

class Patch;

struct ConflictInfo {
    const Patch* existingPatch;
    const Patch* incomingPatch;
    uint64_t conflictStart;
    uint64_t conflictEnd;
    enum class Action { KEEP_EXISTING, REPLACE, MERGE, CANCEL };
};

class PatchConflictDetector {
public:
    static bool hasByteOverlap(const Patch& a, const Patch& b);

    static std::vector<ConflictInfo> findConflicts(
        const Patch& candidate,
        const std::vector<const Patch*>& activePatches);

    static ConflictInfo::Action promptForConflict(
        const ConflictInfo& conflict);
};

} // namespace ghidra::patch
