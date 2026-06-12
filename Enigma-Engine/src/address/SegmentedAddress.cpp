/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/SegmentedAddress.h"
#include "ghidra/SegmentedAddressSpace.h"
#include <cstdio>

namespace ghidra {

SegmentedAddress::SegmentedAddress()
    : base_(), segment_(0), segmentOffset_(0) {}

SegmentedAddress::SegmentedAddress(int64_t flatOffset, SegmentedAddressSpace* space)
    : base_(space, flatOffset), segment_(0), segmentOffset_(0) {
    if (space != nullptr) {
        segment_ = space->getDefaultSegmentFromFlat(flatOffset);
        segmentOffset_ = static_cast<int>(space->getDefaultOffsetFromFlat(flatOffset));
    }
}

SegmentedAddress::SegmentedAddress(SegmentedAddressSpace* space, int segment, int segmentOffset)
    : base_(space,
            space != nullptr ? space->getFlatOffset(segment, segmentOffset) : 0),
      segment_(segment & 0xffff),
      segmentOffset_(segmentOffset & 0xffff) {}

bool SegmentedAddress::operator==(const SegmentedAddress& other) const {
    return base_ == other.base_ && segment_ == other.segment_;
}

std::string SegmentedAddress::toString() const {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04x:%04x", segment_, segmentOffset_);
    return std::string(buf);
}

} // namespace ghidra
