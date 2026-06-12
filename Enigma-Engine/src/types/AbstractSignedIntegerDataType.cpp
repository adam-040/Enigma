/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\AbstractSignedIntegerDataType.h>

namespace ghidra {

AbstractSignedIntegerDataType::AbstractSignedIntegerDataType(const std::string& name, DataTypeManager* dtm)
    : AbstractIntegerDataType(name, dtm) {}

AbstractSignedIntegerDataType::~AbstractSignedIntegerDataType() = default;

bool AbstractSignedIntegerDataType::isSigned() const {
    return true;
}

} // namespace ghidra
