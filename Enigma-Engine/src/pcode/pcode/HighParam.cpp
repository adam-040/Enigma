/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighParam.cpp
/// \brief High-level function parameter.
#include "ghidra/pcode/HighParam.h"
#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

HighParam::HighParam(HighFunction* func) : HighLocal(func) {}

HighParam::HighParam(DataType* tp, Varnode* rep, const Address& pc, int slot, HighSymbol* sym)
    : HighLocal(tp, rep, std::vector<Varnode*>(), pc, sym) {
    setSlot(slot);
}

HighParam::HighParam(int64_t id, const std::string& nm, Varnode* rep,
                     int cat, bool readonly, int slot, int catIndex, HighFunction* func)
    : HighLocal(id, nm, rep, cat, readonly, slot, catIndex, func) {}

void HighParam::decode(Decoder& /*decoder*/) {
    if (symbol) {
        slot = symbol->getCategoryIndex();
    }
}

}  // namespace pcode
}  // namespace ghidra
