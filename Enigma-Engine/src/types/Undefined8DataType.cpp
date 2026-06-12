/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined8DataType.cpp
/// \brief Undefined 8-byte data type.
#include "ghidra/Undefined8DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined8DataType::Undefined8DataType(DataTypeManager* dtm)
    : Undefined("undefined8", dtm, 8) {}

std::string Undefined8DataType::getDescription() const {
    return "Undefined 8-byte";
}

std::string Undefined8DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined8DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        uint64_t v = buf->getLong(0);
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << v << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined8DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined8DataType*>(this);
    }
    return new Undefined8DataType(dtm);
}

} // namespace ghidra
