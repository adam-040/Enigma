/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ThunkReference.cpp
/// \brief Concrete thunk function reference
#include <ghidra/ThunkReference.h>
#include <ghidra/RefType.h>

namespace ghidra {

ThunkReference::ThunkReference(Address thunkAddr, Address thunkedAddr)
    : fromAddr_(thunkAddr), toAddr_(thunkedAddr) {}

const RefType* ThunkReference::getReferenceType() const {
    return &RefTypes::THUNK;
}

std::string ThunkReference::toString() const {
    return "Thunk: " + fromAddr_.toString() + " -> " + toAddr_.toString();
}

bool ThunkReference::operator==(const Reference& other) const {
    return other.getReferenceType() == &RefTypes::THUNK &&
           fromAddr_ == other.getFromAddress() &&
           toAddr_ == other.getToAddress();
}

bool ThunkReference::operator!=(const Reference& other) const {
    return !(*this == other);
}

} // namespace ghidra
