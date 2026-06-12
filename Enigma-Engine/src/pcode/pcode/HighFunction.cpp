/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunction.cpp
/// \brief High-level abstraction associated with a low level function.
#include "ghidra/pcode/HighFunction.h"
#include "ghidra/pcode/HighParam.h"
#include "ghidra/pcode/HighVariable.h"
#include "ghidra/LocalSymbolMap.h"
#include "ghidra/GlobalSymbolMap.h"
#include "ghidra/EquateTable.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"

namespace ghidra {
namespace pcode {

HighFunction::HighFunction()
    : func(nullptr), language(nullptr), compilerSpec(nullptr), dtManager(nullptr),
      equateTable(nullptr), size(0), returnVar(nullptr) {}

HighFunction::HighFunction(void* f, void* lang, void* cs, void* dtm, EquateTable* et)
    : func(f), language(lang), compilerSpec(cs), dtManager(dtm),
      equateTable(et), size(0), returnVar(nullptr) {}

void HighFunction::decode(Decoder& /*decoder*/) {}

void HighFunction::encode(Encoder& /*encoder*/) const {}

void HighFunction::grabFromFunction() {}
void HighFunction::releaseToFunction() {}
void HighFunction::cleanSymbols() {
    paramList.clear();
    variables.clear();
    returnVar = nullptr;
}

}  // namespace pcode
}  // namespace ghidra
