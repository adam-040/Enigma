/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataOrganization.cpp
/// \brief Data organization implementation
#include <ghidra/DataOrganization.h>

namespace ghidra {

bool DataOrganization::isEquivalent(const DataOrganization* obj) const {
    if (!obj) return false;
    if (getAbsoluteMaxAlignment() != obj->getAbsoluteMaxAlignment()) return false;
    if (isBigEndian() != obj->isBigEndian()) return false;
    BitFieldPacking* myBitFieldPacking = getBitFieldPacking();
    BitFieldPacking* otherBitFieldPacking = obj->getBitFieldPacking();
    if (myBitFieldPacking || otherBitFieldPacking) {
        if (!myBitFieldPacking || !otherBitFieldPacking) return false;
        if (!myBitFieldPacking->isEquivalent(otherBitFieldPacking)) return false;
    }
    if (getCharSize() != obj->getCharSize() || getWideCharSize() != obj->getWideCharSize()) return false;
    if (getDefaultAlignment() != obj->getDefaultAlignment()) return false;
    if (getDefaultPointerAlignment() != obj->getDefaultPointerAlignment()) return false;
    if (getDoubleSize() != obj->getDoubleSize() || getFloatSize() != obj->getFloatSize()) return false;
    if (getIntegerSize() != obj->getIntegerSize() || getLongLongSize() != obj->getLongLongSize()) return false;
    if (getShortSize() != obj->getShortSize()) return false;
    if (getLongSize() != obj->getLongSize() || getLongDoubleSize() != obj->getLongDoubleSize()) return false;
    if (isSignedChar() != obj->isSignedChar()) return false;
    if (getMachineAlignment() != obj->getMachineAlignment()) return false;
    if (getPointerSize() != obj->getPointerSize() || getPointerShift() != obj->getPointerShift()) return false;

    std::vector<int> keys = getSizes();
    std::vector<int> op2keys = obj->getSizes();
    if (keys != op2keys) return false;
    for (int k : keys) {
        if (getSizeAlignment(k) != obj->getSizeAlignment(k)) return false;
    }
    return true;
}

} // namespace ghidra
