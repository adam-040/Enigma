/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined6DataType.cpp
/// \brief Undefined 6-byte data type.
#include "ghidra/Undefined6DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined6DataType::Undefined6DataType(DataTypeManager* dtm)
    : Undefined("undefined6", dtm, 6) {}

std::string Undefined6DataType::getDescription() const {
    return "Undefined 6-byte";
}

std::string Undefined6DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined6DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        std::ostringstream ss;
        ss << std::hex << std::uppercase;
        for (int i = 0; i < 6; i++) {
            int b = static_cast<uint8_t>(buf->getByte(i));
            ss << std::setw(2) << std::setfill('0') << b;
        }
        ss << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined6DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined6DataType*>(this);
    }
    return new Undefined6DataType(dtm);
}

} // namespace ghidra
