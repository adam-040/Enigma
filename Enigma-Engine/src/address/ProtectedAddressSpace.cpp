/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/ProtectedAddressSpace.h"

namespace ghidra {

ProtectedAddressSpace::ProtectedAddressSpace(const std::string& name, int unique)
    : SegmentedAddressSpace(name, PROTECTEDMODE_SIZE, unique),
      offsetSize_(PROTECTEDMODE_OFFSETSIZE) {
    int64_t m = 1;
    m <<= offsetSize_;
    m -= 1;
    offsetMask_ = m;
}

int64_t ProtectedAddressSpace::getFlatOffset(int segment, int64_t offset) const {
    int64_t res = static_cast<int64_t>(static_cast<uint64_t>(segment) << offsetSize_);
    return res + offset;
}

int ProtectedAddressSpace::getDefaultSegmentFromFlat(int64_t flat) const {
    return static_cast<int>(static_cast<uint64_t>(flat) >> offsetSize_);
}

int64_t ProtectedAddressSpace::getDefaultOffsetFromFlat(int64_t flat) const {
    return flat & offsetMask_;
}

int64_t ProtectedAddressSpace::getOffsetFromFlat(int64_t flat, int /*segment*/) const {
    return flat & offsetMask_;
}

std::optional<SegmentedAddress> ProtectedAddressSpace::getAddressInSegment(int64_t /*flat*/, int /*preferredSegment*/) const {
    return std::nullopt;
}

int ProtectedAddressSpace::getNextOpenSegment(const Address& addr) const {
    int res = getDefaultSegmentFromFlat(addr.getOffset());
    res = (res + 8) & 0xfff8;
    return res;
}

} // namespace ghidra
