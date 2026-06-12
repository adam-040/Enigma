/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/SegmentedAddressSpace.h"
#include "ghidra/AddressFormatException.h"
#include "ghidra/AddressOutOfBoundsException.h"
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace ghidra {

SegmentedAddressSpace::SegmentedAddressSpace(const std::string& name, int unique)
    : GenericAddressSpace(name, REALMODE_SIZE, AddressSpace::TYPE_RAM, unique) {
    maxOffset_ = REALMODE_MAXOFFSET;
}

SegmentedAddressSpace::SegmentedAddressSpace(const std::string& name, int size, int unique)
    : GenericAddressSpace(name, size, AddressSpace::TYPE_RAM, unique) {}

int64_t SegmentedAddressSpace::getFlatOffset(int segment, int64_t offset) const {
    int64_t res = static_cast<int64_t>(static_cast<uint64_t>(segment) << 4);
    return res + offset;
}

int SegmentedAddressSpace::getDefaultSegmentFromFlat(int64_t flat) const {
    if (flat > 0xFFFFFL) {
        return 0xFFFF;
    }
    return static_cast<int>((flat >> 4) & 0xF000);
}

int64_t SegmentedAddressSpace::getDefaultOffsetFromFlat(int64_t flat) const {
    if (flat > 0xFFFFFL) {
        return flat - 0xFFFF0;
    }
    return flat & 0xFFFFL;
}

int64_t SegmentedAddressSpace::getOffsetFromFlat(int64_t flat, int segment) const {
    return flat - (static_cast<int64_t>(segment) << 4);
}

std::optional<SegmentedAddress> SegmentedAddressSpace::getAddressInSegment(int64_t flat, int preferredSegment) const {
    if ((static_cast<int64_t>(preferredSegment) << 4) <= flat) {
        int64_t off = flat - (static_cast<int64_t>(preferredSegment) << 4);
        if (off <= 0xffff) {
            return SegmentedAddress(const_cast<SegmentedAddressSpace*>(this),
                                    preferredSegment, static_cast<int>(off));
        }
    }
    return std::nullopt;
}

SegmentedAddress SegmentedAddressSpace::getAddress(int segment, int segmentOffset) const {
    if (segmentOffset > 0xffff) {
        throw AddressOutOfBoundsException("Offset is too large.");
    }
    if (segment > 0xffff) {
        throw AddressOutOfBoundsException("Segment is too large.");
    }
    return SegmentedAddress(const_cast<SegmentedAddressSpace*>(this), segment, segmentOffset);
}

int SegmentedAddressSpace::getNextOpenSegment(const Address& addr) const {
    int64_t res = addr.getOffset();
    return static_cast<int>((res >> 4) + 1);
}

Address SegmentedAddressSpace::getAddress(int64_t byteOffset) const {
    return Address(const_cast<SegmentedAddressSpace*>(this), byteOffset);
}

Address SegmentedAddressSpace::getAddressInThisSpaceOnly(int64_t byteOffset) const {
    return Address(const_cast<SegmentedAddressSpace*>(this), byteOffset);
}

static int64_t parseSegHex(const std::string& s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return static_cast<int64_t>(std::stoull(s.substr(2), nullptr, 16));
    }
    return static_cast<int64_t>(std::stoull(s, nullptr, 16));
}

Address SegmentedAddressSpace::getAddress(const std::string& addrString, bool caseSensitive) const {
    (void)caseSensitive;
    std::string s = addrString;
    std::size_t colon = s.find(Address::SEPARATOR_CHAR);
    if (colon == std::string::npos) {
        try {
            int64_t off = parseSegHex(s);
            return Address(const_cast<SegmentedAddressSpace*>(this), off);
        } catch (const std::exception& e) {
            throw AddressFormatException(std::string("Cannot parse (") + s + ") as a number: " + e.what());
        }
    }
    std::string segStr = s.substr(0, colon);
    std::string offStr = s.substr(colon + 1);
    int seg = -1, off = -1;
    try {
        seg = static_cast<int>(parseSegHex(segStr));
        off = static_cast<int>(parseSegHex(offStr));
    } catch (const std::exception& e) {
        throw AddressFormatException(std::string("Cannot parse (") + s + ") as a segmented address: " + e.what());
    }
    return Address(const_cast<SegmentedAddressSpace*>(this), getFlatOffset(seg, off));
}

} // namespace ghidra
