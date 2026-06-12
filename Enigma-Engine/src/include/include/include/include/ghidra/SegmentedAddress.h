/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SegmentedAddress.h
/// \brief Address with explicit segment and 16-bit segment-offset fields.
/// Translated from: ghidra.program.model.address.SegmentedAddress
///
/// The C++ port keeps the underlying Address as a value-typed member.
/// The segment and segment-offset are derived on demand from the
/// address's SegmentedAddressSpace and flat offset.
#pragma once

#include <ghidra/Address.h>
#include <cstdint>
#include <string>

namespace ghidra {

class SegmentedAddressSpace;

/// Address for segmented (real-mode / protected-mode) address spaces.
/// The flat offset encodes both the segment and the segment offset
/// (see SegmentedAddressSpace::getFlatOffset for the exact encoding).
class SegmentedAddress {
public:
    /// Default-constructed (invalid) address.
    SegmentedAddress();

    /// Construct from a flat offset and a segmented address space.
    /// The segment is recovered via the space's getDefaultSegmentFromFlat.
    SegmentedAddress(int64_t flatOffset, SegmentedAddressSpace* space);

    /// Construct with explicit segment and 16-bit segment-offset.
    /// The flat offset is computed via the space's getFlatOffset.
    SegmentedAddress(SegmentedAddressSpace* space, int segment, int segmentOffset);

    /// @return the underlying Address (space + flat offset).
    const Address& getBaseAddress() const { return base_; }

    /// @return the space this address lives in.
    AddressSpace* getAddressSpace() const { return base_.getAddressSpace(); }

    /// @return the flat offset.
    int64_t getOffset() const { return base_.getOffset(); }

    /// @return the 16-bit segment selector.
    int getSegment() const { return segment_; }

    /// @return the 16-bit offset within the segment.
    int getSegmentOffset() const { return segmentOffset_; }

    /// @return true if the address is in a valid space.
    bool isValid() const { return base_.isValid(); }

    std::string toString() const;

    bool operator==(const SegmentedAddress& other) const;
    bool operator!=(const SegmentedAddress& other) const { return !(*this == other); }

private:
    Address base_;
    int segment_;
    int segmentOffset_;
};

} // namespace ghidra
