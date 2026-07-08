#include "ghidra/patch/BytePatch.h"
#include "ghidra/Memory.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace ghidra::patch {

BytePatch::BytePatch(uint64_t address,
                     std::vector<uint8_t> originalBytes,
                     std::vector<uint8_t> patchedBytes,
                     std::string patchName,
                     std::string patchDescription)
    : id_(PatchId::create())
    , address_(address)
    , originalBytes_(std::move(originalBytes))
    , patchedBytes_(std::move(patchedBytes))
    , description_(std::move(patchDescription))
{
    if (patchName.empty()) {
        std::ostringstream oss;
        oss << "Byte patch @ 0x" << std::hex << address;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

bool BytePatch::apply(Memory& memory, ProgramDB& program) {
    (void)program;
    return true;  // Application is handled by PatchMemory overlay
}

bool BytePatch::revert(Memory& memory, ProgramDB& program) {
    (void)program;
    return true;  // Revert is handled by PatchMemory overlay
}

std::string BytePatch::previewText() const {
    std::ostringstream oss;
    oss << "0x" << std::hex << address_ << ": ";
    auto printBytes = [&](const std::vector<uint8_t>& bytes) {
        for (size_t i = 0; i < bytes.size() && i < 16; ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(bytes[i]) << ' ';
        }
        if (bytes.size() > 16) oss << "...";
    };
    printBytes(originalBytes_);
    oss << "-> ";
    printBytes(patchedBytes_);
    oss << "(" << std::dec << patchedBytes_.size() << " bytes)";
    return oss.str();
}

std::vector<uint64_t> BytePatch::affectedAddresses() const {
    std::vector<uint64_t> addrs;
    addrs.reserve(patchedBytes_.size());
    for (uint64_t i = 0; i < patchedBytes_.size(); ++i) {
        addrs.push_back(address_ + i);
    }
    return addrs;
}

bool BytePatch::conflictsWith(const Patch& other) const {
    if (other.originalBytes().empty() && other.patchedBytes().empty()) {
        return false;
    }
    auto otherAffected = other.affectedAddresses();
    auto ourAffected = affectedAddresses();
    std::vector<uint64_t> intersection;
    std::set_intersection(
        ourAffected.begin(), ourAffected.end(),
        otherAffected.begin(), otherAffected.end(),
        std::back_inserter(intersection));
    return !intersection.empty();
}

} // namespace ghidra::patch
