/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParameterPieces.h
/// \brief Basic elements of a parameter: address, data-type, properties
/// Translated from: ghidra.program.model.lang.ParameterPieces
#pragma once

#include <ghidra/Address.h>
#include <ghidra/DataType.h>
#include <ghidra/Varnode.h>
#include <vector>

namespace ghidra {

class Program;

class ParameterPieces {
public:
    Address address;
    DataType* type = nullptr;
    std::vector<Varnode*> joinPieces;
    bool isThisPointer = false;
    bool hiddenReturnPtr = false;
    bool isIndirect = false;

    ParameterPieces() = default;

    void swapMarkup(ParameterPieces& op) {
        std::swap(hiddenReturnPtr, op.hiddenReturnPtr);
        std::swap(isIndirect, op.isIndirect);
        std::swap(isThisPointer, op.isThisPointer);
        std::swap(type, op.type);
        std::swap(joinPieces, op.joinPieces);
    }

    static std::vector<Varnode*> mergeSequence(std::vector<Varnode*>& seq, bool bigEndian);
};

} // namespace ghidra
