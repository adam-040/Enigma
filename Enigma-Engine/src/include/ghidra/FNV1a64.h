#pragma once
#include <cstdint>
#include <cstddef>

namespace ghidra {

class FNV1a64 {
public:
    static constexpr uint64_t OFFSET_BASIS = 0xcbf29ce484222325ULL;
    static constexpr uint64_t PRIME = 0x100000001b3ULL;

    FNV1a64() : hash_(OFFSET_BASIS) {}

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            hash_ ^= static_cast<uint64_t>(data[i]);
            hash_ *= PRIME;
        }
    }

    void updateByte(uint8_t b) {
        hash_ ^= static_cast<uint64_t>(b);
        hash_ *= PRIME;
    }

    uint64_t digest() const { return hash_; }

    void reset() { hash_ = OFFSET_BASIS; }

    static uint64_t hash(const uint8_t* data, size_t len) {
        FNV1a64 h;
        h.update(data, len);
        return h.digest();
    }

private:
    uint64_t hash_;
};

} // namespace ghidra
