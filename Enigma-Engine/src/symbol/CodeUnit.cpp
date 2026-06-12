/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CodeUnit.cpp
/// \brief CodeUnit base class implementation
#include <ghidra/CodeUnit.h>

namespace ghidra {

CodeUnit::CodeUnit(Program* program, Address address, DataType* dataType)
    : program_(program), address_(address), dataType_(dataType) {}

Address CodeUnit::getMaxAddress() const {
    if (!address_.getAddressSpace()) return Address();
    return Address(address_.getAddressSpace(), address_.getOffset() + getLength() - 1);
}

bool CodeUnit::hasReferences() const {
    return !referencesFrom_.empty() || !referencesTo_.empty();
}

} // namespace ghidra
