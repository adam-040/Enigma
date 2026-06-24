#pragma once
#include <cstdint>
#include <functional>

namespace ghidra {

// Custom hash for sequential uint64_t addresses.
// std::hash<uint64_t> is identity, causing collisions on nearby keys.
struct AddressHash {
    size_t operator()(uint64_t v) const {
        v ^= v >> 30;
        v *= 0xbf58476d1ce4e5b9ULL;
        v ^= v >> 27;
        v *= 0x94d049bb133111ebULL;
        v ^= v >> 31;
        return static_cast<size_t>(v);
    }
};

} // namespace ghidra
