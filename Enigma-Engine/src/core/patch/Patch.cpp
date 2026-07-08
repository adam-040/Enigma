#include "ghidra/patch/Patch.h"
#include <random>
#include <sstream>
#include <iomanip>

namespace ghidra::patch {

PatchId PatchId::create() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << dis(gen)
        << std::setw(16) << dis(gen);
    return { oss.str() };
}

Patch::Patch() : createdAt_(std::chrono::system_clock::now()) {}

std::vector<uint8_t> Patch::originalBytes() const { return {}; }
std::vector<uint8_t> Patch::patchedBytes() const { return {}; }
uint64_t Patch::baseAddress() const { return 0; }
uint64_t Patch::size() const { return 0; }
std::vector<uint64_t> Patch::affectedAddresses() const { return {}; }

bool Patch::conflictsWith(const Patch& other) const {
    if (category() != other.category()) return false;
    if (baseAddress() == 0 || other.baseAddress() == 0) return false;
    uint64_t thisEnd = baseAddress() + size();
    uint64_t otherEnd = other.baseAddress() + other.size();
    return baseAddress() < otherEnd && other.baseAddress() < thisEnd;
}

} // namespace ghidra::patch
