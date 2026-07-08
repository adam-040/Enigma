#pragma once

#include "ghidra/patch/BytePatch.h"

namespace ghidra::patch {

class StringPatch : public BytePatch {
public:
    enum class Encoding { ASCII, UTF8, UTF16 };

    StringPatch(uint64_t address,
                const std::string& original,
                const std::string& patched,
                Encoding encoding = Encoding::ASCII,
                std::string patchName = "",
                std::string patchDescription = "");

    PatchCategory category() const override { return PatchCategory::STRING; }
    std::string name() const override { return name_; }
    std::string originalString() const { return originalStr_; }
    std::string patchedString() const { return patchedStr_; }
    Encoding encoding() const { return encoding_; }

private:
    std::string name_;
    std::string originalStr_;
    std::string patchedStr_;
    Encoding encoding_;
};

} // namespace ghidra::patch
