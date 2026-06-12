/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BitFieldPackingImpl.cpp
/// \brief Concrete bitfield packing policy implementation
#include "ghidra/BitFieldPackingImpl.h"

namespace ghidra {

bool BitFieldPackingImpl::useMSConvention() const {
    return useMSConvention_;
}

bool BitFieldPackingImpl::isTypeAlignmentEnabled() const {
    return useMSConvention_ || typeAlignmentEnabled_;
}

int BitFieldPackingImpl::getZeroLengthBoundary() const {
    return useMSConvention_ ? 0 : zeroLengthBoundary_;
}

void BitFieldPackingImpl::setUseMSConvention(bool useMSConvention) {
    useMSConvention_ = useMSConvention;
}

void BitFieldPackingImpl::setTypeAlignmentEnabled(bool typeAlignmentEnabled) {
    typeAlignmentEnabled_ = typeAlignmentEnabled;
}

void BitFieldPackingImpl::setZeroLengthBoundary(int zeroLengthBoundary) {
    zeroLengthBoundary_ = zeroLengthBoundary < 0 ? 0 : zeroLengthBoundary;
}

} // namespace ghidra
