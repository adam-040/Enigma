/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamMeasure.cpp
/// \brief Implementation of ParamMeasure.
#include "ghidra/pcode/ParamMeasure.h"
#include "ghidra/Decoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {
namespace pcode {

ParamMeasure::ParamMeasure() : vn(nullptr), dt(nullptr), rank(0) {}

ParamMeasure::ParamMeasure(Varnode* v, DataType* t, int r) : vn(v), dt(t), rank(r) {}

void ParamMeasure::decode(::ghidra::Decoder& decoder, PcodeFactory* /*factory*/) {
    // Varnode::decode is a higher-level porting concern; this stub
    // captures the rank element that ParamMeasure owns.
    int rankel = decoder.openElement(ELEM_RANK);
    (void)rankel;
    rank = static_cast<int>(decoder.readSignedInteger(ATTRIB_VAL));
    decoder.closeElement(rankel);
}

}  // namespace pcode
}  // namespace ghidra
