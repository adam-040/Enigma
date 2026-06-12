/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IBO64DataType.cpp
/// \brief 64-bit Image Base Offset relative pointer-typedef BuiltIn implementation
#include "ghidra/IBO64DataType.h"
#include "ghidra/PointerTypeSettingsDefinition.h"
#include "ghidra/PointerType.h"

namespace ghidra {

IBO64DataType& IBO64DataType::dataType() {
    static IBO64DataType instance;
    return instance;
}

IBO64DataType::IBO64DataType(DataTypeManager* dtm)
    : AbstractPointerTypedefBuiltIn("ImageBaseOffset64", nullptr, 8, dtm) {
    PointerTypeSettingsDefinition::def().setType(getDefaultSettings(),
        PointerType::IMAGE_BASE_RELATIVE);
}

std::string IBO64DataType::getDescription() const {
    return "64-bit Image Base Offset Relative Pointer-Typedef";
}

std::string IBO64DataType::getMnemonic(Settings* settings) const {
    return "ibo64";
}

DataType* IBO64DataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<IBO64DataType*>(this);
    }
    return new IBO64DataType(dtm);
}

} // namespace ghidra
