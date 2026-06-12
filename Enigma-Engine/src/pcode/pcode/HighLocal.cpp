/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighLocal.cpp
/// \brief High-level local variable.
#include "ghidra/pcode/HighLocal.h"
#include "ghidra/HighSymbol.h"
#include "ghidra/Decoder.h"

namespace ghidra {
namespace pcode {

HighLocal::HighLocal(HighFunction* func) : HighVariable(func), symbol(nullptr), slot(-1), firstUseOffset(0) {}

HighLocal::HighLocal(DataType* type, Varnode* vn, const std::vector<Varnode*>& inst,
                     const Address& pc, HighSymbol* sym)
    : HighVariable(sym ? sym->getName() : std::string(), type, vn, inst,
                   sym ? sym->getHighFunction() : nullptr),
      pcaddr(pc), symbol(sym), slot(-1), firstUseOffset(0) {}

HighLocal::HighLocal(int64_t id, const std::string& nm, Varnode* rep,
                     int cat, bool readonly, int sl, int catIndex, HighFunction* func)
    : HighVariable(func), symbol(nullptr), slot(sl), firstUseOffset(id) {
    name = nm;
    if (rep != nullptr) attachInstances({rep}, rep);
    setCategory(cat, catIndex);
    setReadOnly(readonly);
}

void HighLocal::decode(Decoder& /*decoder*/) {}

}  // namespace pcode
}  // namespace ghidra
