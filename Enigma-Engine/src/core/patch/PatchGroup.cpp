#include "ghidra/patch/PatchGroup.h"
#include "ghidra/patch/PatchManager.h"
#include <algorithm>

namespace ghidra::patch {

PatchGroup::PatchGroup(const std::string& id, const std::string& name)
    : id_(id)
    , name_(name)
{
}

void PatchGroup::addPatch(const std::string& patchId) {
    if (!contains(patchId)) {
        patchIds_.push_back(patchId);
    }
}

void PatchGroup::removePatch(const std::string& patchId) {
    auto it = std::find(patchIds_.begin(), patchIds_.end(), patchId);
    if (it != patchIds_.end()) {
        patchIds_.erase(it);
    }
}

bool PatchGroup::contains(const std::string& patchId) const {
    return std::find(patchIds_.begin(), patchIds_.end(), patchId) != patchIds_.end();
}

void PatchGroup::enableAll(PatchManager& mgr) {
    for (const auto& pid : patchIds_) {
        PatchId id{pid};
        mgr.enablePatch(id);
    }
    enabled_ = true;
}

void PatchGroup::disableAll(PatchManager& mgr) {
    for (const auto& pid : patchIds_) {
        PatchId id{pid};
        mgr.disablePatch(id);
    }
    enabled_ = false;
}

} // namespace ghidra::patch
