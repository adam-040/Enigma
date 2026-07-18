#include "ghidra/patch/CodeCaveAllocator.h"
#include <algorithm>

namespace ghidra::patch {

CodeCaveAllocator::CodeCaveAllocator(const std::vector<SectionInfo>& sections, const BinaryLoader* loader)
    : sections_(sections), loader_(loader) {
}

std::vector<CodeCaveAllocator::CodeCave> CodeCaveAllocator::scanSection(
    const SectionInfo& section, uint64_t minSize) const
{
    std::vector<CodeCave> caves;
    if (!section.isExecutable || !loader_) return caves;
    if (section.virtualSize == 0) return caves;

    // Read the entire section bytes via BinaryLoader
    uint64_t readSize = section.virtualSize;
    if (readSize > 65536) readSize = 65536; // cap at 64KB per section for safety
    auto bytes = loader_->getBytes(section.virtualAddress, static_cast<size_t>(readSize));
    if (bytes.empty()) return caves;

    // Scan for runs of 0x00 bytes
    uint64_t runStart = 0;
    uint64_t runLength = 0;

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] == 0x00) {
            if (runLength == 0) {
                runStart = section.virtualAddress + i;
            }
            ++runLength;
        } else {
            if (runLength >= minSize) {
                caves.push_back({runStart, runLength});
            }
            runLength = 0;
        }
    }
    if (runLength >= minSize) {
        caves.push_back({runStart, runLength});
    }

    return caves;
}

std::optional<CodeCaveAllocator::CodeCave> CodeCaveAllocator::findCodeCave(uint64_t minSize) const {
    if (!loader_ || minSize == 0) return std::nullopt;

    std::vector<CodeCave> allCaves;

    for (const auto& section : sections_) {
        auto caves = scanSection(section, minSize);
        allCaves.insert(allCaves.end(), caves.begin(), caves.end());
    }

    if (allCaves.empty()) return std::nullopt;

    // Determine which section is .text (first executable section with "text" in name)
    uint64_t textEnd = 0;
    for (const auto& section : sections_) {
        if (section.isExecutable && section.name.find(".text") != std::string::npos) {
            textEnd = section.virtualAddress + section.virtualSize;
        }
    }

    // Sort: prefer caves near end-of-.text, then larger caves
    std::sort(allCaves.begin(), allCaves.end(),
        [textEnd](const CodeCave& a, const CodeCave& b) {
            uint64_t distA = (a.address >= textEnd) ? 0 : (textEnd - a.address);
            uint64_t distB = (b.address >= textEnd) ? 0 : (textEnd - b.address);
            if (distA != distB) return distA < distB;
            return a.availableSize > b.availableSize;
        });

    return allCaves.front();
}

} // namespace ghidra::patch
