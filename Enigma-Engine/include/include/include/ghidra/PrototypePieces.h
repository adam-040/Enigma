/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PrototypePieces.h
/// \brief Raw components of a function prototype (obtained from parsing source code)
/// Translated from: ghidra.program.model.lang.PrototypePieces
#pragma once

#include <ghidra/DataType.h>
#include <vector>

namespace ghidra {

class PrototypeModel;

class PrototypePieces {
public:
    PrototypeModel* model = nullptr;
    DataType* outtype = nullptr;
    std::vector<DataType*> intypes;
    int firstVarArgSlot = -1;

    PrototypePieces() = default;
    PrototypePieces(PrototypeModel* m, DataType* out, std::vector<DataType*> ins,
                    int varArg = -1)
        : model(m), outtype(out), intypes(std::move(ins)), firstVarArgSlot(varArg) {}
};

} // namespace ghidra
