#pragma once

#include "ghidra/BinaryLoader.h"
#include <vector>
#include <cstdint>
#include <optional>

namespace ghidra::patch {

class CodeCaveAllocator {
public:
    struct CodeCave {
        uint64_t address;
        uint64_t availableSize;
    };

    CodeCaveAllocator(const std::vector<SectionInfo>& sections, const BinaryLoader* loader);

    // Find a code cave of at least minSize bytes in an executable section.
    // Prefers end-of-.text sections, then larger caves.
    std::optional<CodeCave> findCodeCave(uint64_t minSize) const;

private:
    const std::vector<SectionInfo>& sections_;
    const BinaryLoader* loader_;

    // Scan a section for runs of 0x00 bytes
    std::vector<CodeCave> scanSection(const SectionInfo& section, uint64_t minSize) const;
};

} // namespace ghidra::patch
