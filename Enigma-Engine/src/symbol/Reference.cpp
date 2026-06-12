/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Reference.cpp
/// \brief Base Reference class implementations
#include <ghidra/Reference.h>
#include <sstream>

namespace ghidra {

bool Reference::operator==(const Reference& other) const {
    return getFromAddress() == other.getFromAddress() &&
           getToAddress() == other.getToAddress() &&
           getOperandIndex() == other.getOperandIndex();
}

bool Reference::operator!=(const Reference& other) const {
    return !(*this == other);
}

} // namespace ghidra
