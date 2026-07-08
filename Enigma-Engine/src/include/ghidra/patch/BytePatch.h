#pragma once

#include "ghidra/patch/Patch.h"

namespace ghidra::patch {

class BytePatch : public Patch {
public:
    BytePatch(uint64_t address,
              std::vector<uint8_t> originalBytes,
              std::vector<uint8_t> patchedBytes,
              std::string patchName = "",
              std::string patchDescription = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::BYTE; }
    std::string name() const override { return name_; }
    std::string description() const override { return description_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;

    std::string previewText() const override;
    std::vector<uint8_t> originalBytes() const override { return originalBytes_; }
    std::vector<uint8_t> patchedBytes() const override { return patchedBytes_; }

    uint64_t baseAddress() const override { return address_; }
    uint64_t size() const override { return static_cast<uint64_t>(patchedBytes_.size()); }
    std::vector<uint64_t> affectedAddresses() const override;

    bool conflictsWith(const Patch& other) const override;

    void setOriginalBytes(const std::vector<uint8_t>& bytes) { originalBytes_ = bytes; }

private:
    PatchId id_;
    uint64_t address_;
    std::vector<uint8_t> originalBytes_;
    std::vector<uint8_t> patchedBytes_;
    std::string name_;
    std::string description_;
};

} // namespace ghidra::patch
