/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamMeasure.h
/// \brief A measured parameter slot used by the HighParamID family.
/// Translated from: ghidra.program.model.pcode.ParamMeasure
#pragma once

#include <ghidra/Varnode.h>
#include <ghidra/DataType.h>
#include <cstdint>

namespace ghidra {

class Decoder;
class PcodeFactory;

namespace pcode {

/**
 * ParamMeasure: a per-input/output parameter measurement (Varnode, DataType, rank)
 * collected by the decompiler's parameter-id machinery.
 */
class ParamMeasure {
public:
    ParamMeasure();
    ParamMeasure(Varnode* vn, DataType* dt, int rank);

    bool isEmpty() const { return vn == nullptr; }

    void decode(Decoder& decoder, PcodeFactory* factory);

    Varnode* getVarnode() const { return vn; }
    DataType* getDataType() const { return dt; }
    int getRank() const { return rank; }

    void setVarnode(Varnode* v) { vn = v; }
    void setDataType(DataType* t) { dt = t; }
    void setRank(int r) { rank = r; }

private:
    Varnode* vn;
    DataType* dt;
    int rank;
};

}  // namespace pcode
}  // namespace ghidra
