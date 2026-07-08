#pragma once

#include "ghidra/patch/BytePatch.h"

namespace ghidra::patch {

class NopFillPatch : public BytePatch {
public:
    NopFillPatch(uint64_t address, uint64_t fillSize,
                 uint8_t fillByte = 0x90,
                 std::string patchName = "",
                 std::string patchDescription = "");

    PatchCategory category() const override { return PatchCategory::NOP_FILL; }
    std::string name() const override { return name_; }

private:
    std::string name_;
};

} // namespace ghidra::patch
