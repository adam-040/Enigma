/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Undefined4DataType.cpp
/// \brief Undefined 4-byte data type.
#include "ghidra/Undefined4DataType.h"
#include "ghidra/MemBuffer.h"
#include <sstream>
#include <iomanip>

namespace ghidra {

Undefined4DataType::Undefined4DataType(DataTypeManager* dtm)
    : Undefined("undefined4", dtm, 4) {}

std::string Undefined4DataType::getDescription() const {
    return "Undefined 4-byte";
}

std::string Undefined4DataType::getMnemonic(Settings* /*settings*/) const {
    return getName();
}

std::string Undefined4DataType::getRepresentation(MemBuffer* buf, Settings* /*settings*/, int /*length*/) const {
    if (buf == nullptr) return "??";
    try {
        uint32_t v = buf->getInt(0);
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v << "h";
        return ss.str();
    } catch (...) {
        return "??";
    }
}

DataType* Undefined4DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<Undefined4DataType*>(this);
    }
    return new Undefined4DataType(dtm);
}

} // namespace ghidra
