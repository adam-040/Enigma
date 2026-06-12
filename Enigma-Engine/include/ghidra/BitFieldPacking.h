/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BitFieldPacking.h
/// \brief Bitfield packing policy used by a DataOrganization.
#pragma once

namespace ghidra {

class BitFieldPacking {
public:
    virtual ~BitFieldPacking() = default;

    virtual bool useMSConvention() const = 0;
    virtual bool isTypeAlignmentEnabled() const = 0;
    virtual int getZeroLengthBoundary() const = 0;

    virtual bool isEquivalent(const BitFieldPacking* other) const {
        if (!other) return false;
        return useMSConvention() == other->useMSConvention() &&
               isTypeAlignmentEnabled() == other->isTypeAlignmentEnabled() &&
               getZeroLengthBoundary() == other->getZeroLengthBoundary();
    }
};

} // namespace ghidra
