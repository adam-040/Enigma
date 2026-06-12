/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProtectedAddressSpace.h
/// \brief x86 16-bit protected-mode segmented address space.
/// Translated from: ghidra.program.model.address.ProtectedAddressSpace
#pragma once

#include <ghidra/SegmentedAddressSpace.h>
#include <ghidra/SegmentedAddress.h>
#include <cstdint>
#include <optional>

namespace ghidra {

/// Address space for x86 16-bit protected-mode programs. The segment
/// (selector) and the segment-offset are packed into the 32-bit flat
/// offset with the selector in the high 16 bits and the offset in the
/// low 16 bits. Unlike real-mode, the same flat offset has a unique
/// segment:offset encoding in protected mode.
class ProtectedAddressSpace : public SegmentedAddressSpace {
public:
    static constexpr int PROTECTEDMODE_SIZE = 32;
    static constexpr int PROTECTEDMODE_OFFSETSIZE = 16;

    explicit ProtectedAddressSpace(const std::string& name, int unique);

    int64_t getFlatOffset(int segment, int64_t offset) const override;
    int getDefaultSegmentFromFlat(int64_t flat) const override;
    int64_t getDefaultOffsetFromFlat(int64_t flat) const override;
    int64_t getOffsetFromFlat(int64_t flat, int segment) const override;
    std::optional<SegmentedAddress> getAddressInSegment(int64_t flat, int preferredSegment) const override;
    int getNextOpenSegment(const Address& addr) const override;

private:
    int offsetSize_;
    int64_t offsetMask_;
};

} // namespace ghidra
