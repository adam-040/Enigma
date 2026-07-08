#include "ghidra/patch/PatchManager.h"
#include "ghidra/patch/BytePatch.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/Memory.h"
#include "ghidra/BinaryLoader.h"
#include "ghidra/Address.h"
#include "ghidra/AddressFactory.h"
#include <algorithm>
#include <fstream>

namespace ghidra::patch {

PatchManager::PatchManager()
    : patchMemory_(std::make_unique<PatchMemory>(nullptr))
{
}

PatchManager::~PatchManager() = default;

void PatchManager::setProgram(ProgramDB* program) {
    program_ = program;
}

void PatchManager::setBinaryLoader(BinaryLoader* loader) {
    loader_ = loader;
}

void PatchManager::installPatchMemory(ProgramDB* programDB) {
    if (!programDB) return;
    auto originalMem = programDB->releaseMemory();
    if (!originalMem) return;
    patchMemory_ = std::make_unique<PatchMemory>(std::move(originalMem));
    programDB->setMemory(patchMemory_.get());
}

void PatchManager::addPatch(std::unique_ptr<Patch> patch) {
    auto id = patch->id();
    patches_[id.id] = std::move(patch);

    if (id.id == patches_[id.id]->id().id) {
        if (patches_[id.id]->enabled()) {
            doApplyPatch(*patches_[id.id]);
        }
        firePatchAdded(id);
    }
}

void PatchManager::removePatch(const PatchId& id) {
    auto it = patches_.find(id.id);
    if (it == patches_.end()) return;

    if (it->second->applied() && it->second->enabled()) {
        doRevertPatch(*it->second);
    }
    patches_.erase(it);
    firePatchRemoved(id);
}

Patch* PatchManager::getPatch(const PatchId& id) {
    auto it = patches_.find(id.id);
    return (it != patches_.end()) ? it->second.get() : nullptr;
}

const Patch* PatchManager::getPatch(const PatchId& id) const {
    auto it = patches_.find(id.id);
    return (it != patches_.end()) ? it->second.get() : nullptr;
}

std::vector<Patch*> PatchManager::getAllPatches() {
    std::vector<Patch*> result;
    result.reserve(patches_.size());
    for (auto& [_, p] : patches_) {
        result.push_back(p.get());
    }
    return result;
}

std::vector<const Patch*> PatchManager::getAllPatches() const {
    std::vector<const Patch*> result;
    result.reserve(patches_.size());
    for (auto& [_, p] : patches_) {
        result.push_back(p.get());
    }
    return result;
}

std::vector<Patch*> PatchManager::getActivePatches() {
    std::vector<Patch*> result;
    for (auto& [_, p] : patches_) {
        if (p->enabled() && p->applied()) {
            result.push_back(p.get());
        }
    }
    return result;
}

std::vector<const Patch*> PatchManager::getActivePatchesByCategory(PatchCategory cat) const {
    std::vector<const Patch*> result;
    for (auto& [_, p] : patches_) {
        if (p->enabled() && p->applied() && p->category() == cat) {
            result.push_back(p.get());
        }
    }
    return result;
}

bool PatchManager::enablePatch(const PatchId& id) {
    auto it = patches_.find(id.id);
    if (it == patches_.end()) return false;
    auto& patch = *it->second;

    if (!patch.enabled()) {
        // Check for conflicts
        auto active = getActivePatches();
        std::vector<const Patch*> constActive(active.begin(), active.end());
        auto conflicts = PatchConflictDetector::findConflicts(patch, constActive);

        if (!conflicts.empty() && conflictHandler_) {
            for (auto& conflict : conflicts) {
                auto action = conflictHandler_(conflict);
                if (action == ConflictInfo::Action::CANCEL) return false;
                if (action == ConflictInfo::Action::REPLACE) {
                    disablePatch(conflict.existingPatch->id());
                }
            }
        }

        patch.setEnabled(true);
        if (doApplyPatch(patch)) {
            firePatchEnabled(id);
            return true;
        }
    }
    return false;
}

void PatchManager::disablePatch(const PatchId& id) {
    auto it = patches_.find(id.id);
    if (it == patches_.end()) return;
    auto& patch = *it->second;

    if (patch.enabled()) {
        patch.setEnabled(false);
        if (doRevertPatch(patch)) {
            firePatchDisabled(id);
        }
    }
}

void PatchManager::togglePatch(const PatchId& id) {
    auto it = patches_.find(id.id);
    if (it == patches_.end()) return;
    if (it->second->enabled()) {
        disablePatch(id);
    } else {
        enablePatch(id);
    }
}

void PatchManager::applyAllActive() {
    for (auto& [_, p] : patches_) {
        if (p->enabled() && !p->applied()) {
            doApplyPatch(*p);
        }
    }
}

void PatchManager::revertAll() {
    for (auto& [_, p] : patches_) {
        if (p->applied()) {
            doRevertPatch(*p);
        }
    }
}

PatchGroup* PatchManager::createGroup(const std::string& name) {
    auto id = PatchId::create();
    auto group = std::make_unique<PatchGroup>(id.id, name);
    auto* ptr = group.get();
    groups_[id.id] = std::move(group);
    if (onGroupChanged_) onGroupChanged_(id.id);
    return ptr;
}

void PatchManager::removeGroup(const std::string& groupId) {
    groups_.erase(groupId);
    if (onGroupChanged_) onGroupChanged_(groupId);
}

PatchGroup* PatchManager::getGroup(const std::string& groupId) {
    auto it = groups_.find(groupId);
    return (it != groups_.end()) ? it->second.get() : nullptr;
}

void PatchManager::addPatchToGroup(const PatchId& pid, const std::string& gid) {
    auto* group = getGroup(gid);
    if (group) {
        group->addPatch(pid.id);
        auto* patch = getPatch(pid);
        if (patch) patch->setGroupId(gid);
        if (onGroupChanged_) onGroupChanged_(gid);
    }
}

void PatchManager::removePatchFromGroup(const PatchId& pid, const std::string& gid) {
    auto* group = getGroup(gid);
    if (group) {
        group->removePatch(pid.id);
        auto* patch = getPatch(pid);
        if (patch) patch->setGroupId("");
        if (onGroupChanged_) onGroupChanged_(gid);
    }
}

void PatchManager::enableGroup(const std::string& gid) {
    auto* group = getGroup(gid);
    if (group) group->enableAll(*this);
}

void PatchManager::disableGroup(const std::string& gid) {
    auto* group = getGroup(gid);
    if (group) group->disableAll(*this);
}

bool PatchManager::exportPatchedBinary(const std::string& outputPath) {
    if (!loader_ || !program_) return false;

    std::vector<uint8_t> output = loader_->getRawDataCopy();

    auto bytePatches = getActivePatchesByCategory(PatchCategory::BYTE);
    for (const auto* patch : bytePatches) {
        uint64_t addr = patch->baseAddress();
        auto bytes = patch->patchedBytes();
        if (bytes.empty()) continue;

        uint64_t fileOffset = loader_->virtualAddressToFileOffset(addr);
        if (fileOffset != UINT64_MAX && fileOffset + bytes.size() <= output.size()) {
            std::copy(bytes.begin(), bytes.end(), output.begin() + static_cast<ptrdiff_t>(fileOffset));
        }
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(output.data()),
              static_cast<std::streamsize>(output.size()));
    return bool(out);
}

std::vector<ConflictInfo> PatchManager::findConflicts(const Patch& candidate) const {
    std::vector<const Patch*> active;
    for (auto& [_, p] : patches_) {
        if (p->enabled() && p->applied()) {
            active.push_back(p.get());
        }
    }
    return PatchConflictDetector::findConflicts(candidate, active);
}

void PatchManager::setConflictHandler(
    std::function<ConflictInfo::Action(const ConflictInfo&)> handler)
{
    conflictHandler_ = std::move(handler);
}

size_t PatchManager::activePatchCount() const {
    size_t count = 0;
    for (auto& [_, p] : patches_) {
        if (p->enabled() && p->applied()) ++count;
    }
    return count;
}

bool PatchManager::doApplyPatch(Patch& patch) {
    if (!program_ || patch.applied()) return false;

    Memory& mem = *program_->getMemory();

    // Byte-level patches: write to PatchMemory overlay
    if (!patch.originalBytes().empty() || !patch.patchedBytes().empty()) {
        auto bytes = patch.patchedBytes();
        if (!bytes.empty()) {
            patchMemory_->applyPatch(bytes, patch.baseAddress());
        }
    }

    // Metadata patches: apply to ProgramDB directly
    if (patch.apply(mem, *program_)) {
        patch.setApplied(true);
        return true;
    }

    // If apply fails but bytes were set in overlay, still mark applied for rollback
    if (!patch.patchedBytes().empty()) {
        patch.setApplied(true);
        return true;
    }
    return false;
}

bool PatchManager::doRevertPatch(Patch& patch) {
    if (!program_ || !patch.applied()) return false;

    Memory& mem = *program_->getMemory();

    // Byte-level: remove from PatchMemory overlay
    if (!patch.patchedBytes().empty()) {
        patchMemory_->removePatch(patch.baseAddress(), patch.size());
    }

    // Metadata: revert in ProgramDB
    patch.revert(mem, *program_);

    patch.setApplied(false);
    return true;
}

void PatchManager::firePatchAdded(const PatchId& id) {
    if (onPatchAdded_) onPatchAdded_(id);
}

void PatchManager::firePatchRemoved(const PatchId& id) {
    if (onPatchRemoved_) onPatchRemoved_(id);
}

void PatchManager::firePatchEnabled(const PatchId& id) {
    if (onPatchEnabled_) onPatchEnabled_(id);
}

void PatchManager::firePatchDisabled(const PatchId& id) {
    if (onPatchDisabled_) onPatchDisabled_(id);
}

} // namespace ghidra::patch
