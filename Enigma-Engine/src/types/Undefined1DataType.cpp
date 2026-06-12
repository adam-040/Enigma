/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined1DataType.cpp
/// \brief Undefined 1-byte data type.
#include "ghidra/Undefined1DataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/Scalar.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined1DataType::Undefined1DataType(DataTypeManager* dtm)
    : Undefined("undefined1", dtm, 1) {}

std::string Undefined1DataType::getDescription() const {
    return "Undefined Byte";
}

std::string Undefined1DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined1DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        uint8_t b = static_cast<uint8_t>(buf->getByte(0));
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b) << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined1DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined1DataType*>(this);
    }
    return new Undefined1DataType(dtm);
}

} // namespace ghidra
