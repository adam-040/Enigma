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
/// \brief Base class for instructions and data in the program listing
/// Translated from: ghidra.program.model.listing.CodeUnit

#include <ghidra/CodeUnit.h>
#include <ghidra/DataType.h>

namespace ghidra {

CodeUnit::CodeUnit(Program* program, Address address, DataType* dataType)
    : program_(program), address_(address), dataType_(dataType) {}

Address CodeUnit::getMaxAddress() const {
    if (!dataType_) return address_;
    return address_.addNoWrap(dataType_->getLength() - 1);
}

bool CodeUnit::hasReferences() const {
    return !referencesFrom_.empty() || !referencesTo_.empty();
}

} // namespace ghidra
