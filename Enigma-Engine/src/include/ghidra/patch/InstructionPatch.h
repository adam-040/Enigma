#pragma once

#include "ghidra/patch/Patch.h"
#include "ghidra/Assembler.h"
#include <string>

namespace ghidra::patch {

class InstructionPatch : public Patch {
public:
    InstructionPatch(uint64_t address,
                     std::string assemblyText,
                     std::string patchName = "",
                     std::string patchDescription = "");

    InstructionPatch(uint64_t address,
                     std::string assemblyText,
                     uint64_t originalSize,
                     std::string patchName = "",
                     std::string patchDescription = "");

    PatchId id() const override { return id_; }
    PatchCategory category() const override { return PatchCategory::INSTRUCTION; }
    std::string name() const override { return name_; }
    std::string description() const override { return description_; }

    bool apply(Memory& memory, ProgramDB& program) override;
    bool revert(Memory& memory, ProgramDB& program) override;

    std::string previewText() const override;
    std::vector<uint8_t> originalBytes() const override { return originalBytes_; }
    std::vector<uint8_t> patchedBytes() const override { return patchedBytes_; }

    uint64_t baseAddress() const override { return address_; }
    uint64_t size() const override;
    std::vector<uint64_t> affectedAddresses() const override;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> additionalWrites() const override;
    std::vector<std::pair<uint64_t, uint64_t>> getRelocationEntries() const override;

    bool conflictsWith(const Patch& other) const override;

    const std::string& assemblyText() const { return assemblyText_; }
    bool isAssembled() const { return assembled_; }
    const std::string& assembleError() const { return assembleError_; }

    uint64_t originalSize() const { return originalSize_; }
    uint64_t newSize() const { return newSize_; }
    bool sizeMismatch() const { return sizeMismatch_; }
    bool isBlocked() const { return blocked_; }

    // Trampoline mode: original site contains JMP to cave, cave contains new code + JMP back
    bool isTrampolineMode() const { return trampolineMode_; }
    uint64_t caveAddress() const { return caveAddress_; }
    const std::vector<uint8_t>& caveBytes() const { return caveBytes_; }
    uint64_t consumedSize() const { return consumedSize_; }
    // Called by PatchManager to configure trampoline after cave allocation
    void setTrampoline(uint64_t caveAddr, std::vector<uint8_t> siteBytes,
                       std::vector<uint8_t> cave, uint64_t consumed);

    // GUI transparency: trampoline metadata accessors
    std::string getTrampolineCaveAddressHex() const;
    bool isJumpToCave(uint64_t address) const;

private:
    PatchId id_;
    uint64_t address_;
    std::string assemblyText_;
    std::vector<uint8_t> originalBytes_;
    std::vector<uint8_t> patchedBytes_;
    std::string name_;
    std::string description_;
    bool assembled_ = false;
    std::string assembleError_;
    uint64_t originalSize_ = 0;
    uint64_t newSize_ = 0;
    bool sizeMismatch_ = false;
    bool blocked_ = false;

    // Trampoline state
    bool trampolineMode_ = false;
    uint64_t caveAddress_ = 0;
    std::vector<uint8_t> caveBytes_;
    uint64_t consumedSize_ = 0;

    // Relocation: absolute address references within patched bytes
    std::vector<AsmResult::AbsoluteRef> absoluteRefs_;
};

} // namespace ghidra::patch
