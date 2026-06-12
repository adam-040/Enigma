/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SegmentedAddressSpace.h
/// \brief Segmented address space (x86 real-mode, etc.).
/// Translated from: ghidra.program.model.address.SegmentedAddressSpace
#pragma once

#include <ghidra/AddressSpace.h>
#include <ghidra/SegmentedAddress.h>
#include <cstdint>
#include <optional>

namespace ghidra {

/// Address space that produces SegmentedAddress values. The flat
/// offset is encoded by getFlatOffset(segment, segmentOffset); the
/// reverse mapping is provided by getDefaultSegmentFromFlat and
/// getDefaultOffsetFromFlat. Subclasses (notably ProtectedAddressSpace)
/// override these to use a different encoding.
class SegmentedAddressSpace : public GenericAddressSpace {
public:
    static constexpr int REALMODE_SIZE = 21;
    static constexpr int64_t REALMODE_MAXOFFSET = 0x10FFEF;
    static constexpr int POINTER_SIZE = 2;

    /// Construct a real-mode (x86 16-bit) segmented address space.
    SegmentedAddressSpace(const std::string& name, int unique);

    /// Construct a segmented address space with custom flat-address
    /// size. Used by ProtectedAddressSpace and any other subclass
    /// that does not match the real-mode 21-bit size.
    SegmentedAddressSpace(const std::string& name, int size, int unique);

    virtual ~SegmentedAddressSpace() = default;

    /// Encode (segment, segmentOffset) into a flat byte offset.
    /// Default encoding: real-mode `seg << 4 | off`.
    virtual int64_t getFlatOffset(int segment, int64_t offset) const;

    /// Extract the 16-bit segment portion of a flat offset using the
    /// default mapping.
    virtual int getDefaultSegmentFromFlat(int64_t flat) const;

    /// Extract the segment-offset portion of a flat offset using the
    /// default mapping.
    virtual int64_t getDefaultOffsetFromFlat(int64_t flat) const;

    /// Extract the segment-offset portion assuming a specific segment.
    virtual int64_t getOffsetFromFlat(int64_t flat, int segment) const;

    /// Try to create a SegmentedAddress that maps to `flat` and is
    /// encoded in `preferredSegment`. The returned optional is empty
    /// if the encoding is not representable in that segment.
    virtual std::optional<SegmentedAddress> getAddressInSegment(int64_t flat, int preferredSegment) const;

    /// Build a SegmentedAddress for the given (segment, segmentOffset) pair.
    SegmentedAddress getAddress(int segment, int segmentOffset) const;

    /// Extract the segment selector from a flat Address in this space.
    int getSegmentFromAddress(const Address& addr) const {
        return getDefaultSegmentFromFlat(addr.getOffset());
    }

    /// Get the segment index for the first segment whose start address
    /// comes after the given address.
    virtual int getNextOpenSegment(const Address& addr) const;

    Address getAddress(int64_t byteOffset) const override;
    Address getAddressInThisSpaceOnly(int64_t byteOffset) const override;
    Address getAddress(const std::string& addrString, bool caseSensitive) const override;

    int getPointerSize() const override { return POINTER_SIZE; }
    AddressSpace* getPhysicalSpace() override { return this; }
};

} // namespace ghidra
