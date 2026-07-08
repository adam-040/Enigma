#include "ghidra/patch/PatchConflictDetector.h"
#include "ghidra/patch/Patch.h"
#include <algorithm>

namespace ghidra::patch {

bool PatchConflictDetector::hasByteOverlap(const Patch& a, const Patch& b) {
    auto aAddrs = a.affectedAddresses();
    auto bAddrs = b.affectedAddresses();
    if (aAddrs.empty() || bAddrs.empty()) return false;

    std::vector<uint64_t> intersection;
    std::set_intersection(
        aAddrs.begin(), aAddrs.end(),
        bAddrs.begin(), bAddrs.end(),
        std::back_inserter(intersection));
    return !intersection.empty();
}

std::vector<ConflictInfo> PatchConflictDetector::findConflicts(
    const Patch& candidate,
    const std::vector<const Patch*>& activePatches)
{
    std::vector<ConflictInfo> conflicts;
    for (const auto* existing : activePatches) {
        if (existing->id().id == candidate.id().id) continue;
        if (!hasByteOverlap(candidate, *existing)) continue;

        auto cAddrs = candidate.affectedAddresses();
        auto eAddrs = existing->affectedAddresses();
        std::vector<uint64_t> common;
        std::set_intersection(
            cAddrs.begin(), cAddrs.end(),
            eAddrs.begin(), eAddrs.end(),
            std::back_inserter(common));

        if (!common.empty()) {
            conflicts.push_back({
                existing,
                &candidate,
                common.front(),
                common.back() + 1
            });
        }
    }
    return conflicts;
}

ConflictInfo::Action PatchConflictDetector::promptForConflict(
    const ConflictInfo& conflict)
{
    (void)conflict;
    return ConflictInfo::Action::CANCEL;
}

} // namespace ghidra::patch
