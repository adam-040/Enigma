#pragma once

#include <string>
#include <vector>

namespace ghidra::patch {

class PatchManager;

class PatchGroup {
public:
    PatchGroup(const std::string& id, const std::string& name);

    const std::string& id() const { return id_; }
    const std::string& name() const { return name_; }
    void setName(const std::string& name) { name_ = name; }

    void addPatch(const std::string& patchId);
    void removePatch(const std::string& patchId);
    const std::vector<std::string>& patchIds() const { return patchIds_; }
    bool contains(const std::string& patchId) const;

    void enableAll(PatchManager& mgr);
    void disableAll(PatchManager& mgr);

    bool enabled() const { return enabled_; }
    void setEnabled(bool e) { enabled_ = e; }

private:
    std::string id_;
    std::string name_;
    std::vector<std::string> patchIds_;
    bool enabled_ = true;
};

} // namespace ghidra::patch
