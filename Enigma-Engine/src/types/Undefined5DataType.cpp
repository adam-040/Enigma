/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined5DataType.cpp
/// \brief Undefined 5-byte data type.
#include "ghidra/Undefined5DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined5DataType::Undefined5DataType(DataTypeManager* dtm)
    : Undefined("undefined5", dtm, 5) {}

std::string Undefined5DataType::getDescription() const {
    return "Undefined 5-byte";
}

std::string Undefined5DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined5DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        std::ostringstream ss;
        ss << std::hex << std::uppercase;
        for (int i = 0; i < 5; i++) {
            int b = static_cast<uint8_t>(buf->getByte(i));
            ss << std::setw(2) << std::setfill('0') << b;
        }
        ss << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined5DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined5DataType*>(this);
    }
    return new Undefined5DataType(dtm);
}

} // namespace ghidra
