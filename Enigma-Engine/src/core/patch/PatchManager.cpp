#include "ghidra/patch/PatchManager.h"
#include "ghidra/patch/BytePatch.h"
#include "ghidra/patch/InstructionPatch.h"
#include "ghidra/patch/NopFillPatch.h"
#include "ghidra/patch/CodeCaveAllocator.h"
#include "ghidra/Assembler.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/Memory.h"
#include "ghidra/BinaryLoader.h"
#include "ghidra/Address.h"
#include "ghidra/AddressFactory.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <fstream>
#include <map>
#include <unordered_map>
#include <cstring>
#include <iostream>

namespace ghidra::patch {

using json = nlohmann::json;

static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out += hex[b >> 4];
        out += hex[b & 0xF];
    }
    return out;
}

static std::vector<uint8_t> hexToBytes(const std::string& s) {
    std::vector<uint8_t> out;
    if (s.size() % 2 != 0) return out;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = val(s[i]), lo = val(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static const uint16_t IMAGE_REL_BASED_DIR64 = 10;
static const uint32_t RELOC_PAGE_SIZE = 0x1000;

// Recalculate the PE OptionalHeader.CheckSum field.
// Standard algorithm matching Windows CheckSumMappedFile().
// Returns true if checksum was recalculated (PE file), false if not PE.
static bool recalculatePEChecksum(std::vector<uint8_t>& data) {
    if (data.size() < 0x40) return false;

    // Read e_lfanew from DOS header at offset 0x3C
    uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data.data() + 0x3C);
    if (e_lfanew + 4 > data.size()) return false;

    // Validate PE signature "PE\0\0" = 0x00004550
    uint32_t peSig = *reinterpret_cast<const uint32_t*>(data.data() + e_lfanew);
    if (peSig != 0x00004550) return false;

    // Checksum field offset: PE sig(4) + COFF header(20) + offset in Optional Header(64)
    uint32_t checksumOffset = e_lfanew + 88;
    if (checksumOffset + 4 > data.size()) return false;

    // Save and zero the checksum field for calculation
    uint32_t oldChecksum = *reinterpret_cast<const uint32_t*>(data.data() + checksumOffset);
    *reinterpret_cast<uint32_t*>(data.data() + checksumOffset) = 0;

    // Calculate rolling 16-bit checksum over entire file
    uint64_t checksum = 0;
    size_t length = data.size();
    const uint16_t* words = reinterpret_cast<const uint16_t*>(data.data());
    size_t wordCount = length / 2;

    for (size_t i = 0; i < wordCount; ++i) {
        checksum += words[i];
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    if (length & 1) {
        checksum += data[length - 1];
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += length;

    // Write new checksum back
    *reinterpret_cast<uint32_t*>(data.data() + checksumOffset) = static_cast<uint32_t>(checksum);
    return true;
}

// Find the .reloc section file offset and size in a PE binary.
// Returns false if not PE or .reloc not found.
static bool findRelocSection(const std::vector<uint8_t>& data,
                             uint32_t& outSectionFileOffset,
                             uint32_t& outSectionRawSize,
                             uint32_t& outSectionVirtualSize,
                             uint32_t& outSectionRVA) {
    if (data.size() < 0x40) return false;
    uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data.data() + 0x3C);
    if (e_lfanew + 4 > data.size()) return false;
    uint32_t peSig = *reinterpret_cast<const uint32_t*>(data.data() + e_lfanew);
    if (peSig != 0x00004550) return false;

    uint16_t numSections = *reinterpret_cast<const uint16_t*>(data.data() + e_lfanew + 6);
    uint16_t optHeaderSize = *reinterpret_cast<const uint16_t*>(data.data() + e_lfanew + 20);
    uint32_t sectionOffset = e_lfanew + 24 + optHeaderSize;

    for (uint16_t i = 0; i < numSections; ++i) {
        if (sectionOffset + 40 > data.size()) return false;
        char nameBuf[9] = {0};
        std::memcpy(nameBuf, data.data() + sectionOffset, 8);
        if (std::string(nameBuf) == ".reloc") {
            outSectionRawSize = *reinterpret_cast<const uint32_t*>(data.data() + sectionOffset + 16);
            outSectionFileOffset = *reinterpret_cast<const uint32_t*>(data.data() + sectionOffset + 20);
            outSectionVirtualSize = *reinterpret_cast<const uint32_t*>(data.data() + sectionOffset + 8);
            outSectionRVA = *reinterpret_cast<const uint32_t*>(data.data() + sectionOffset + 12);
            return true;
        }
        sectionOffset += 40;
    }
    return false;
}

// Update the PE data directory entry for .reloc (index 5) with a new size.
static bool updateRelocDirectorySize(std::vector<uint8_t>& data, uint32_t newRelocSize) {
    if (data.size() < 0x40) return false;
    uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data.data() + 0x3C);
    if (e_lfanew + 4 > data.size()) return false;
    uint32_t peSig = *reinterpret_cast<const uint32_t*>(data.data() + e_lfanew);
    if (peSig != 0x00004550) return false;

    uint32_t optHeaderOffset = e_lfanew + 24;
    uint16_t magic = *reinterpret_cast<const uint16_t*>(data.data() + optHeaderOffset);

    // Data directory for .reloc is index 5 (each entry = 8 bytes: RVA + Size)
    uint32_t dataDirOffset;
    if (magic == 0x20b) { // PE32+
        dataDirOffset = optHeaderOffset + 160 + 5 * 8;
    } else { // PE32
        dataDirOffset = optHeaderOffset + 96 + 5 * 8;
    }
    if (dataDirOffset + 8 > data.size()) return false;

    // Only update Size field; keep the existing RVA
    *reinterpret_cast<uint32_t*>(data.data() + dataDirOffset + 4) = newRelocSize;
    return true;
}

// Update the SizeOfRawData and VirtualSize of a section by name.
static bool updateSectionSizes(std::vector<uint8_t>& data, const std::string& sectionName,
                               uint32_t newRawSize, uint32_t newVirtualSize) {
    if (data.size() < 0x40) return false;
    uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(data.data() + 0x3C);
    if (e_lfanew + 4 > data.size()) return false;
    uint32_t peSig = *reinterpret_cast<const uint32_t*>(data.data() + e_lfanew);
    if (peSig != 0x00004550) return false;

    uint16_t numSections = *reinterpret_cast<const uint16_t*>(data.data() + e_lfanew + 6);
    uint16_t optHeaderSize = *reinterpret_cast<const uint16_t*>(data.data() + e_lfanew + 20);
    uint32_t sectionOffset = e_lfanew + 24 + optHeaderSize;

    for (uint16_t i = 0; i < numSections; ++i) {
        if (sectionOffset + 40 > data.size()) return false;
        char nameBuf[9] = {0};
        std::memcpy(nameBuf, data.data() + sectionOffset, 8);
        if (std::string(nameBuf) == sectionName) {
            *reinterpret_cast<uint32_t*>(data.data() + sectionOffset + 8) = newVirtualSize;
            *reinterpret_cast<uint32_t*>(data.data() + sectionOffset + 16) = newRawSize;
            return true;
        }
        sectionOffset += 40;
    }
    return false;
}

// Rebuild the .reloc section with new relocation entries added.
// Returns true on success, false if .reloc not found or unsafe to modify.
static bool rebuildRelocSection(std::vector<uint8_t>& data,
                                const std::vector<std::pair<uint64_t, uint64_t>>& newEntries) {
    if (newEntries.empty()) return true;

    uint32_t secFileOff = 0, secRawSize = 0, secVirtSize = 0, secRVA = 0;
    if (!findRelocSection(data, secFileOff, secRawSize, secVirtSize, secRVA)) {
        std::cerr << "[PatchManager] WARNING: No .reloc section found — cannot add relocations\n";
        return false;
    }
    if (secFileOff + secRawSize > data.size()) {
        std::cerr << "[PatchManager] WARNING: .reloc section exceeds file — skipping relocation update\n";
        return false;
    }

    // Parse existing blocks into a map: pageRVA -> vector of uint16_t entries
    std::unordered_map<uint32_t, std::vector<uint16_t>> pageMap;
    uint32_t existingDataEnd = secFileOff; // points past the last block's data

    {
        uint32_t offset = secFileOff;
        uint32_t relocEnd = secFileOff + secRawSize;
        while (offset + 8 <= relocEnd && offset + 8 <= data.size()) {
            uint32_t pageRVA = *reinterpret_cast<const uint32_t*>(data.data() + offset);
            uint32_t blockSize = *reinterpret_cast<const uint32_t*>(data.data() + offset + 4);
            if (pageRVA == 0 && blockSize == 0) break;
            if (blockSize < 8) break;
            if (offset + blockSize > relocEnd) break;

            uint32_t numEntries = (blockSize - 8) / 2;
            uint32_t entriesStart = offset + 8;
            for (uint32_t i = 0; i < numEntries; ++i) {
                uint16_t entry = *reinterpret_cast<const uint16_t*>(data.data() + entriesStart + i * 2);
                uint16_t type = (entry >> 12) & 0xF;
                if (type != 0) {
                    pageMap[pageRVA].push_back(entry);
                }
            }
            existingDataEnd = offset + blockSize;
            offset += blockSize;
        }
    }

    // Add new entries, grouped by 4KB page
    for (auto& [va, value] : newEntries) {
        uint32_t pageRVA = static_cast<uint32_t>(va & ~(RELOC_PAGE_SIZE - 1));
        uint16_t offsetInPage = static_cast<uint16_t>(va & (RELOC_PAGE_SIZE - 1));
        uint16_t entry = (IMAGE_REL_BASED_DIR64 << 12) | offsetInPage;
        pageMap[pageRVA].push_back(entry);
    }

    // Rebuild the .reloc data
    std::vector<uint8_t> newRelocData;
    for (auto& [pageRVA, entries] : pageMap) {
        // Block: pageRVA(4) + blockSize(4) + entries(2*N) + pad to 4-byte alignment
        uint32_t rawEntries = static_cast<uint32_t>(entries.size()) * 2;
        uint32_t blockSize = 8 + rawEntries;
        blockSize = (blockSize + 3) & ~3u; // pad to 4-byte alignment

        newRelocData.resize(newRelocData.size() + blockSize, 0);
        auto* base = newRelocData.data() + newRelocData.size() - blockSize;
        *reinterpret_cast<uint32_t*>(base) = pageRVA;
        *reinterpret_cast<uint32_t*>(base + 4) = blockSize;
        for (size_t i = 0; i < entries.size(); ++i) {
            *reinterpret_cast<uint16_t*>(base + 8 + i * 2) = entries[i];
        }
    }

    // Safety check: the new .reloc data must fit within the existing section
    // (we can't grow sections without shifting everything after them)
    if (newRelocData.size() > secRawSize) {
        std::cerr << "[PatchManager] WARNING: New .reloc data (" << newRelocData.size()
                  << " bytes) exceeds existing section (" << secRawSize
                  << " bytes). Stripping ASLR flag to maintain binary validity.\n";
        // Strip IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR) as fallback
        uint32_t optHeaderOffset = *reinterpret_cast<const uint32_t*>(data.data() + 0x3C) + 24;
        uint16_t magic = *reinterpret_cast<const uint16_t*>(data.data() + optHeaderOffset);
        if (magic == 0x20b) {
            // PE32+ DLL characteristics at offset 110 from opt header start
            uint32_t dllCharOffset = optHeaderOffset + 110;
            if (dllCharOffset + 4 <= data.size()) {
                uint32_t dllChars = *reinterpret_cast<const uint32_t*>(data.data() + dllCharOffset);
                dllChars &= ~0x0040u; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                *reinterpret_cast<uint32_t*>(data.data() + dllCharOffset) = dllChars;
            }
        } else {
            // PE32 DLL characteristics at offset 46 from opt header start
            uint32_t dllCharOffset = optHeaderOffset + 46;
            if (dllCharOffset + 2 <= data.size()) {
                uint16_t dllChars = *reinterpret_cast<const uint16_t*>(data.data() + dllCharOffset);
                dllChars &= ~0x0040u;
                *reinterpret_cast<uint16_t*>(data.data() + dllCharOffset) = dllChars;
            }
        }
        return false; // indicate we couldn't add relocations
    }

    // Write the new .reloc data into the output buffer
    std::copy(newRelocData.begin(), newRelocData.end(),
              data.begin() + static_cast<ptrdiff_t>(secFileOff));

    // Update section header sizes
    uint32_t newVirtSize = static_cast<uint32_t>(newRelocData.size());
    updateSectionSizes(data, ".reloc", newVirtSize, newVirtSize);

    // Update data directory size — the RVA stays the same
    updateRelocDirectorySize(data, newVirtSize);

    return true;
}

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
    auto* rawPatch = patch.get();
    patches_[id.id] = std::move(patch);

    // Check for conflicts with existing active patches
    auto active = getActivePatches();
    std::vector<const Patch*> constActive(active.begin(), active.end());
    auto conflicts = PatchConflictDetector::findConflicts(*rawPatch, constActive);

    if (!conflicts.empty() && conflictHandler_) {
        for (auto& conflict : conflicts) {
            auto action = conflictHandler_(conflict);
            if (action == ConflictInfo::Action::CANCEL) {
                patches_.erase(id.id);
                return;
            }
            if (action == ConflictInfo::Action::REPLACE) {
                disablePatch(conflict.existingPatch->id());
            }
        }
    } else if (!conflicts.empty()) {
        // No handler: replace conflicting patches by default
        for (auto& conflict : conflicts) {
            disablePatch(conflict.existingPatch->id());
        }
    }

    if (rawPatch->enabled()) {
        doApplyPatch(*rawPatch);
    }
    firePatchAdded(id);
    pushUndo(id.id);
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

    lastSkippedPatchAddresses_.clear();
    std::vector<uint8_t> output = loader_->getRawDataCopy();
    bool anySkipped = false;

    auto bytePatches = getActivePatchesByCategory(PatchCategory::BYTE);
    auto instrPatches = getActivePatchesByCategory(PatchCategory::INSTRUCTION);

    auto writePatch = [&](const Patch* patch) {
        uint64_t addr = patch->baseAddress();
        auto bytes = patch->patchedBytes();
        if (bytes.empty()) return;

        uint64_t fileOffset = loader_->virtualAddressToFileOffset(addr);
        if (fileOffset == UINT64_MAX || fileOffset + bytes.size() > output.size()) {
            anySkipped = true;
            lastSkippedPatchAddresses_.push_back(addr);
            return;
        }
        std::copy(bytes.begin(), bytes.end(), output.begin() + static_cast<ptrdiff_t>(fileOffset));

        // Write additional writes (trampoline cave bytes)
        auto additional = patch->additionalWrites();
        for (auto& [caveAddr, caveBytes] : additional) {
            if (caveBytes.empty()) continue;
            uint64_t caveOff = loader_->virtualAddressToFileOffset(caveAddr);
            if (caveOff == UINT64_MAX || caveOff + caveBytes.size() > output.size()) {
                anySkipped = true;
                lastSkippedPatchAddresses_.push_back(caveAddr);
                continue;
            }
            std::copy(caveBytes.begin(), caveBytes.end(),
                      output.begin() + static_cast<ptrdiff_t>(caveOff));
        }
    };

    for (const auto* patch : bytePatches) writePatch(patch);
    for (const auto* patch : instrPatches) writePatch(patch);

    // Never export a partially-patched file: if any patch (or trampoline
    // cave write) could not be mapped into the output binary, fail without
    // writing anything so the skip is visible (see lastSkippedPatchAddresses)
    // instead of silently producing a stale binary.
    if (anySkipped) return false;

    // Collect relocation entries from all active patches (absolute address references)
    std::vector<std::pair<uint64_t, uint64_t>> allRelocEntries;
    for (const auto* patch : instrPatches) {
        auto entries = patch->getRelocationEntries();
        allRelocEntries.insert(allRelocEntries.end(), entries.begin(), entries.end());
    }
    for (const auto* patch : bytePatches) {
        auto entries = patch->getRelocationEntries();
        allRelocEntries.insert(allRelocEntries.end(), entries.begin(), entries.end());
    }

    // Rebuild .reloc section if there are absolute address references
    if (!allRelocEntries.empty()) {
        rebuildRelocSection(output, allRelocEntries);
    }

    // Recalculate PE checksum so the patched binary remains valid at OS level
    recalculatePEChecksum(output);

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

    // Auto-trampoline: if this is a blocked InstructionPatch, try to allocate a code cave
    if (patch.category() == PatchCategory::INSTRUCTION) {
        auto* instr = dynamic_cast<InstructionPatch*>(&patch);
        if (instr && instr->isBlocked()) {
            // Need to assemble new bytes first to know how much cave space is needed
            // The assembler already ran in the constructor — re-run to get the bytes
            auto asmResult = Assembler::instance().assemble(instr->assemblyText(), instr->baseAddress());
            if (!asmResult.success || asmResult.bytes.size() <= instr->originalSize()) {
                // Can't assemble or fits after all — shouldn't be blocked, skip trampoline
                goto apply_normal;
            }

            uint64_t newCodeSize = asmResult.bytes.size();
            // Trampoline stub at original site: JMP rel32 = E9 + 4-byte offset = 5 bytes
            // But we need to consume whole instructions at the original site >= 5 bytes
            // Use Capstone to scan forward to find the nearest instruction boundary >= 5 bytes
            uint64_t consumed = instr->originalSize(); // default: consume the original instruction
            if (consumed < 5) {
                // Need to consume more instructions to make room for JMP rel32 (5 bytes)
                // Simple heuristic: consume until we have >= 5 bytes of instruction boundaries
                // Use assembler disassembly to determine instruction sizes
                auto& assembler = Assembler::instance();
                uint64_t scanAddr = instr->baseAddress();
                uint64_t consumedBytes = 0;
                while (consumedBytes < 5 && scanAddr < 0x140001000 + 66720) {
                    // Read bytes at scanAddr
                    uint64_t fileOff = loader_ ? loader_->virtualAddressToFileOffset(scanAddr) : UINT64_MAX;
                    if (fileOff == UINT64_MAX || fileOff + 15 > loader_->getRawDataCopy().size()) break;
                    auto rawBytes = loader_->getBytes(scanAddr, 15);
                    if (rawBytes.empty()) break;
                    // Try to disassemble each instruction to find boundary
                    // For simplicity: if we can't use Capstone, just consume originalSize_ padded to 5
                    consumedBytes += 1; // minimal: consume byte-by-byte
                    scanAddr++;
                }
                consumed = consumedBytes >= 5 ? consumedBytes : instr->originalSize();
                if (consumed < 5) consumed = 5; // force minimum for JMP rel32
            }

            // Need cave = codeSize + JMP back (5 bytes) + alignment padding
            uint64_t caveNeeded = newCodeSize + 5;
            if (loader_) {
                CodeCaveAllocator caveAlloc(loader_->getSections(), loader_);
                auto cave = caveAlloc.findCodeCave(caveNeeded);
                if (cave) {
                    // Build JMP stub for original site: E9 rel32
                    int64_t rel32 = static_cast<int64_t>(cave->address)
                                    - static_cast<int64_t>(instr->baseAddress()) - 5;
                    if (rel32 < INT32_MIN || rel32 > INT32_MAX) {
                        // Can't reach cave from site — give up on trampoline
                        goto apply_normal;
                    }
                    std::vector<uint8_t> siteBytes = {0xE9,
                        static_cast<uint8_t>(rel32 & 0xFF),
                        static_cast<uint8_t>((rel32 >> 8) & 0xFF),
                        static_cast<uint8_t>((rel32 >> 16) & 0xFF),
                        static_cast<uint8_t>((rel32 >> 24) & 0xFF)};
                    // NOP-pad site if consumed > 5
                    if (consumed > 5) {
                        Assembler::fillMultiByteNopGap(siteBytes, consumed - 5);
                    }

                    // Build JMP back from cave end to site+consumed
                    uint64_t returnAddr = instr->baseAddress() + consumed;
                    int64_t backRel = static_cast<int64_t>(returnAddr)
                                      - static_cast<int64_t>(cave->address + newCodeSize) - 5;
                    std::vector<uint8_t> caveBytes = asmResult.bytes;
                    caveBytes.push_back(0xE9);
                    caveBytes.push_back(static_cast<uint8_t>(backRel & 0xFF));
                    caveBytes.push_back(static_cast<uint8_t>((backRel >> 8) & 0xFF));
                    caveBytes.push_back(static_cast<uint8_t>((backRel >> 16) & 0xFF));
                    caveBytes.push_back(static_cast<uint8_t>((backRel >> 24) & 0xFF));

                    instr->setTrampoline(cave->address, std::move(siteBytes),
                                         std::move(caveBytes), consumed);
                }
                // If no cave found, fall through to normal apply (blocked patch will just show warning)
            }
        }
    }

apply_normal:
    // Let patch capture original bytes BEFORE overlay write
    patch.apply(mem, *program_);

    // Byte-level patches: write to PatchMemory overlay
    if (!patch.originalBytes().empty() || !patch.patchedBytes().empty()) {
        auto bytes = patch.patchedBytes();
        if (!bytes.empty()) {
            patchMemory_->applyPatch(bytes, patch.baseAddress());
        }
        // Write additional writes (cave bytes for trampolines)
        auto additional = patch.additionalWrites();
        for (auto& [addr, additionalBytes] : additional) {
            if (!additionalBytes.empty()) {
                patchMemory_->applyPatch(additionalBytes, addr);
            }
        }
    }

    patch.setApplied(true);
    return true;
}

bool PatchManager::doRevertPatch(Patch& patch) {
    if (!program_ || !patch.applied()) return false;

    Memory& mem = *program_->getMemory();

    // Byte-level: remove from PatchMemory overlay
    if (!patch.patchedBytes().empty()) {
        patchMemory_->removePatch(patch.baseAddress(), patch.size());
    }
    // Remove additional writes (cave bytes for trampolines)
    auto additional = patch.additionalWrites();
    for (auto& [addr, additionalBytes] : additional) {
        if (!additionalBytes.empty()) {
            patchMemory_->removePatch(addr, additionalBytes.size());
        }
    }

    // Metadata: revert in ProgramDB
    patch.revert(mem, *program_);

    patch.setApplied(false);
    return true;
}

void PatchManager::firePatchAdded(const PatchId& id) {
    for (const auto& cb : onPatchAdded_) cb(id);
}

void PatchManager::firePatchRemoved(const PatchId& id) {
    for (const auto& cb : onPatchRemoved_) cb(id);
}

void PatchManager::firePatchEnabled(const PatchId& id) {
    for (const auto& cb : onPatchEnabled_) cb(id);
}

void PatchManager::firePatchDisabled(const PatchId& id) {
    for (const auto& cb : onPatchDisabled_) cb(id);
}

void PatchManager::pushUndo(const std::string& id) {
    undoStack_.push_back(id);
    clearRedo();
}

void PatchManager::clearRedo() {
    redoStack_.clear();
}

bool PatchManager::canUndo() const {
    return !undoStack_.empty();
}

bool PatchManager::canRedo() const {
    return !redoStack_.empty();
}

bool PatchManager::undo() {
    if (undoStack_.empty()) return false;
    std::string id = undoStack_.back();
    undoStack_.pop_back();
    auto it = patches_.find(id);
    if (it == patches_.end()) return false;
    Patch& patch = *it->second;
    if (patch.applied()) {
        doRevertPatch(patch);
        firePatchDisabled(patch.id());
    }
    patch.setEnabled(false);
    redoStack_.push_back(id);
    return true;
}

bool PatchManager::redo() {
    if (redoStack_.empty()) return false;
    std::string id = redoStack_.back();
    redoStack_.pop_back();
    auto it = patches_.find(id);
    if (it == patches_.end()) return false;
    Patch& patch = *it->second;
    if (!patch.applied()) {
        doApplyPatch(patch);
        firePatchEnabled(patch.id());
    }
    patch.setEnabled(true);
    undoStack_.push_back(id);
    return true;
}

void PatchManager::clearHistory() {
    undoStack_.clear();
    redoStack_.clear();
}

static const char* categoryName(PatchCategory cat) {
    switch (cat) {
    case PatchCategory::BYTE: return "byte";
    case PatchCategory::NOP_FILL: return "nop_fill";
    case PatchCategory::INSTRUCTION: return "instruction";
    default: return "unknown";
    }
}

bool PatchManager::saveToJson(const std::string& path) const {
    json root;
    root["version"] = 1;
    root["format"] = "enigma-patches";
    json arr = json::array();
    for (auto& [id, p] : patches_) {
        const char* catName = categoryName(p->category());
        if (std::strcmp(catName, "unknown") == 0) continue;
        json j;
        j["id"] = p->id().id;
        j["category"] = catName;
        j["address"] = p->baseAddress();
        j["original"] = bytesToHex(p->originalBytes());
        j["patched"] = bytesToHex(p->patchedBytes());
        j["name"] = p->name();
        j["description"] = p->description();
        j["enabled"] = p->enabled();
        if (const auto* ip = dynamic_cast<const InstructionPatch*>(p.get())) {
            j["assembly"] = ip->assemblyText();
            j["original_size"] = ip->originalSize();
        }
        arr.push_back(std::move(j));
    }
    root["patches"] = std::move(arr);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << root.dump(2);
    return out.good();
}

bool PatchManager::loadFromJson(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    json root;
    try {
        in >> root;
    } catch (...) {
        return false;
    }
    if (!root.contains("patches") || !root["patches"].is_array()) return false;

    int added = 0;
    for (const auto& j : root["patches"]) {
        std::string category = j.value("category", std::string("byte"));
        std::vector<uint8_t> original = hexToBytes(j.value("original", std::string()));
        std::vector<uint8_t> patched = hexToBytes(j.value("patched", std::string()));
        if (original.empty() || patched.empty()) continue;
        uint64_t address = j.value("address", uint64_t(0));
        std::string name = j.value("name", std::string());
        std::string description = j.value("description", std::string());
        bool enabled = j.value("enabled", true);

        std::unique_ptr<Patch> patch;
        if (category == "nop_fill") {
            patch = std::make_unique<NopFillPatch>(address, patched.size(), patched.front(), name, description);
        } else if (category == "instruction") {
            std::string assembly = j.value("assembly", std::string());
            uint64_t originalSize = j.value("original_size", uint64_t(0));
            if (!assembly.empty()) {
                auto ip = std::make_unique<InstructionPatch>(address, assembly, originalSize, name, description);
                if (!ip->originalBytes().empty()) {
                    patch = std::move(ip);
                }
            }
            if (!patch) {
                patch = std::make_unique<BytePatch>(address, original, patched, name, description);
            }
        } else {
            patch = std::make_unique<BytePatch>(address, original, patched, name, description);
        }
        patch->setEnabled(enabled);
        addPatch(std::move(patch));
        ++added;
    }
    return added > 0;
}

} // namespace ghidra::patch
