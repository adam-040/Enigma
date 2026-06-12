/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IBO32DataType.cpp
/// \brief 32-bit Image Base Offset relative pointer-typedef BuiltIn implementation
#include "ghidra/IBO32DataType.h"
#include "ghidra/PointerTypeSettingsDefinition.h"
#include "ghidra/PointerType.h"

namespace ghidra {

IBO32DataType& IBO32DataType::dataType() {
    static IBO32DataType instance;
    return instance;
}

IBO32DataType::IBO32DataType(DataTypeManager* dtm)
    : AbstractPointerTypedefBuiltIn("ImageBaseOffset32", nullptr, 4, dtm) {
    PointerTypeSettingsDefinition::def().setType(getDefaultSettings(),
        PointerType::IMAGE_BASE_RELATIVE);
}

std::string IBO32DataType::getDescription() const {
    return "32-bit Image Base Offset Relative Pointer-Typedef";
}

std::string IBO32DataType::getMnemonic(Settings* settings) const {
    return "ibo32";
}

DataType* IBO32DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<IBO32DataType*>(this);
    }
    return new IBO32DataType(dtm);
}

} // namespace ghidra
