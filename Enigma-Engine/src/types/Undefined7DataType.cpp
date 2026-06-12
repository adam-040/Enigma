/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined7DataType.cpp
/// \brief Undefined 7-byte data type.
#include "ghidra/Undefined7DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined7DataType::Undefined7DataType(DataTypeManager* dtm)
    : Undefined("undefined7", dtm, 7) {}

std::string Undefined7DataType::getDescription() const {
    return "Undefined 7-byte";
}

std::string Undefined7DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined7DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        std::ostringstream ss;
        ss << std::hex << std::uppercase;
        for (int i = 0; i < 7; i++) {
            int b = static_cast<uint8_t>(buf->getByte(i));
            ss << std::setw(2) << std::setfill('0') << b;
        }
        ss << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined7DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined7DataType*>(this);
    }
    return new Undefined7DataType(dtm);
}

} // namespace ghidra
