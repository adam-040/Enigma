/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Varnode.cpp
/// \brief Varnode implementation - a variable node in pcode
#include "ghidra/Varnode.h"
#include "ghidra/Language.h"

namespace ghidra {

bool Varnode::rangeIntersects(long otherOffset, long otherEndOffset) const {
    long endOffset = offset;
    if (size > 0) endOffset = offset + size - 1;
    if (offset > endOffset) {
        if (otherOffset > otherEndOffset) return true;
        return offset <= otherEndOffset;
    }
    if (otherOffset > otherEndOffset) return endOffset >= otherOffset;
    return offset <= otherEndOffset && endOffset >= otherOffset;
}

bool Varnode::contains(Address addr) const {
    if (spaceID != addr.getAddressSpace()->getSpaceID()) return false;
    if (isConstant() || isHash()) return offset == addr.getOffset();

    long endOffset = offset;
    if (size > 0) endOffset = offset + size - 1;
    long addrOffset = addr.getOffset();
    if (offset > endOffset) return offset <= addrOffset;
    return offset <= addrOffset && endOffset >= addrOffset;
}

bool Varnode::intersects(const Varnode& vn) const {
    if (spaceID != vn.spaceID) return false;
    if (isConstant() || isHash()) return offset == vn.offset;

    long endOtherOffset = vn.offset;
    if (vn.size > 0) endOtherOffset = vn.offset + vn.size - 1;
    return rangeIntersects(vn.offset, endOtherOffset);
}

bool Varnode::isContiguous(const Varnode& lo, bool bigEndian) const {
    AddressSpace* spc = address.getAddressSpace();
    if (spc != lo.address.getAddressSpace()) return false;
    if (bigEndian) {
        long nextoff = spc->truncateOffset(offset + size);
        return nextoff == lo.offset;
    } else {
        long nextoff = spc->truncateOffset(lo.offset + lo.size);
        return nextoff == offset;
    }
}

void Varnode::trim() {
    if (address.getAddressSpace()->getType() == AddressSpace::TYPE_CONSTANT) {
        static const uint64_t masks[] = { 0ULL, 0xffULL, 0xffffULL, 0xffffffULL, 0xffffffffULL, 0xffffffffffULL,
                                      0xffffffffffffULL, 0xffffffffffffffULL, 0xffffffffffffffffULL };
        offset = static_cast<long>(static_cast<uint64_t>(offset) & masks[size]);
        address = Address(address.getAddressSpace(), offset);
    }
}

std::string Varnode::toString(const Language& lang) const {
    return toString();
}

} // namespace ghidra
