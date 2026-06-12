/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined2DataType.cpp
/// \brief Undefined 2-byte data type.
#include "ghidra/Undefined2DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined2DataType::Undefined2DataType(DataTypeManager* dtm)
    : Undefined("undefined2", dtm, 2) {}

std::string Undefined2DataType::getDescription() const {
    return "Undefined 2-byte";
}

std::string Undefined2DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined2DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        uint16_t v = buf->getShort(0);
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined2DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined2DataType*>(this);
    }
    return new Undefined2DataType(dtm);
}

} // namespace ghidra
