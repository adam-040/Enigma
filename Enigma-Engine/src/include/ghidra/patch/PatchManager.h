#pragma once

#include "ghidra/patch/Patch.h"
#include "ghidra/patch/PatchMemory.h"
#include "ghidra/patch/PatchGroup.h"
#include "ghidra/patch/PatchConflictDetector.h"
#include <memory>
#include <map>
#include <vector>
#include <functional>

namespace ghidra {

class ProgramDB;
class BinaryLoader;
class Memory;

namespace patch {

class BytePatch;

class PatchManager {
public:
    PatchManager();
    ~PatchManager();

    void setProgram(ProgramDB* program);
    ProgramDB* program() const { return program_; }

    void setBinaryLoader(BinaryLoader* loader);
    BinaryLoader* binaryLoader() const { return loader_; }

    // PatchMemory access
    PatchMemory* patchMemory() { return patchMemory_.get(); }
    void releasePatchMemory() { patchMemory_.release(); }
    void installPatchMemory(ProgramDB* programDB);

    // Registry
    void addPatch(std::unique_ptr<Patch> patch);
    void removePatch(const PatchId& id);
    Patch* getPatch(const PatchId& id);
    const Patch* getPatch(const PatchId& id) const;
    std::vector<Patch*> getAllPatches();
    std::vector<const Patch*> getAllPatches() const;
    std::vector<Patch*> getActivePatches();
    std::vector<const Patch*> getActivePatchesByCategory(PatchCategory cat) const;

    // Enable/disable with conflict detection
    bool enablePatch(const PatchId& id);
    void disablePatch(const PatchId& id);
    void togglePatch(const PatchId& id);
    void applyAllActive();
    void revertAll();

    // Groups
    PatchGroup* createGroup(const std::string& name);
    void removeGroup(const std::string& groupId);
    PatchGroup* getGroup(const std::string& groupId);
    void addPatchToGroup(const PatchId& pid, const std::string& gid);
    void removePatchFromGroup(const PatchId& pid, const std::string& gid);
    void enableGroup(const std::string& gid);
    void disableGroup(const std::string& gid);

    // Export
    bool exportPatchedBinary(const std::string& outputPath);

    /// Patch addresses that could not be mapped to the output file during
    /// the last export attempt (export returns false when non-empty).
    const std::vector<uint64_t>& lastSkippedPatchAddresses() const {
        return lastSkippedPatchAddresses_;
    }

    // JSON persistence (byte-level patches: BytePatch/NopFillPatch/InstructionPatch)
    bool saveToJson(const std::string& path) const;
    bool loadFromJson(const std::string& path);

    // Conflict detection
    std::vector<ConflictInfo> findConflicts(const Patch& candidate) const;
    void setConflictHandler(std::function<ConflictInfo::Action(const ConflictInfo&)> handler);

    // Callbacks (multi-subscriber: every registered callback fires)
    using PatchCallback = std::function<void(const PatchId&)>;
    void setOnPatchAdded(PatchCallback cb) { onPatchAdded_.push_back(std::move(cb)); }
    void setOnPatchRemoved(PatchCallback cb) { onPatchRemoved_.push_back(std::move(cb)); }
    void setOnPatchEnabled(PatchCallback cb) { onPatchEnabled_.push_back(std::move(cb)); }
    void setOnPatchDisabled(PatchCallback cb) { onPatchDisabled_.push_back(std::move(cb)); }
    void setOnPatchGroupChanged(std::function<void(const std::string&)> cb) {
        onGroupChanged_ = std::move(cb);
    }

    size_t patchCount() const { return patches_.size(); }
    size_t activePatchCount() const;
    size_t groupCount() const { return groups_.size(); }

    bool hasUnsavedChanges() const { return !patches_.empty(); }

    // Undo/Redo
    bool canUndo() const;
    bool canRedo() const;
    bool undo();
    bool redo();
    void clearHistory();

private:
    ProgramDB* program_ = nullptr;
    BinaryLoader* loader_ = nullptr;
    std::unique_ptr<PatchMemory> patchMemory_;

    std::map<std::string, std::unique_ptr<Patch>> patches_;
    std::map<std::string, std::unique_ptr<PatchGroup>> groups_;

    std::vector<PatchCallback> onPatchAdded_;
    std::vector<PatchCallback> onPatchRemoved_;
    std::vector<PatchCallback> onPatchEnabled_;
    std::vector<PatchCallback> onPatchDisabled_;
    std::function<void(const std::string&)> onGroupChanged_;
    std::function<ConflictInfo::Action(const ConflictInfo&)> conflictHandler_;

    // Undo/redo stacks (store PatchId strings)
    std::vector<std::string> undoStack_;
    std::vector<std::string> redoStack_;
    void pushUndo(const std::string& id);
    void clearRedo();

    /// Addresses skipped by the last export (see lastSkippedPatchAddresses).
    std::vector<uint64_t> lastSkippedPatchAddresses_;

    bool doApplyPatch(Patch& patch);
    bool doRevertPatch(Patch& patch);
    void firePatchAdded(const PatchId& id);
    void firePatchRemoved(const PatchId& id);
    void firePatchEnabled(const PatchId& id);
    void firePatchDisabled(const PatchId& id);
};

} // namespace patch
} // namespace ghidra
