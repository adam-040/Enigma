/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined3DataType.cpp
/// \brief Undefined 3-byte data type.
#include "ghidra/Undefined3DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined3DataType::Undefined3DataType(DataTypeManager* dtm)
    : Undefined("undefined3", dtm, 3) {}

std::string Undefined3DataType::getDescription() const {
    return "Undefined 3-byte";
}

std::string Undefined3DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined3DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        int b0 = static_cast<uint8_t>(buf->getByte(0));
        int b1 = static_cast<uint8_t>(buf->getByte(1));
        int b2 = static_cast<uint8_t>(buf->getByte(2));
        std::ostringstream ss;
        ss << std::hex << std::uppercase
           << std::setw(2) << std::setfill('0') << b0
           << std::setw(2) << std::setfill('0') << b1
           << std::setw(2) << std::setfill('0') << b2 << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined3DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined3DataType*>(this);
    }
    return new Undefined3DataType(dtm);
}

} // namespace ghidra
