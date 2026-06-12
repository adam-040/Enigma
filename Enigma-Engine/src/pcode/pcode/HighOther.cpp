/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighOther.cpp
/// \brief Other forms of variable.
#include "ghidra/pcode/HighOther.h"
#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

HighOther::HighOther(HighFunction* func) : HighVariable(func), symbol(nullptr), slot(-1) {}

HighOther::HighOther(DataType* type, Varnode* vn, const std::vector<Varnode*>& inst,
                     const Address& pc, HighSymbol* sym)
    : HighVariable(sym ? sym->getName() : std::string(), type, vn, inst,
                   sym ? sym->getHighFunction() : nullptr),
      pcaddr(pc), symbol(sym), slot(-1) {}

HighOther::HighOther(int64_t id, const std::string& nm, Varnode* rep,
                     int cat, int sl, HighFunction* func)
    : HighVariable(func), symbol(nullptr), slot(sl) {
    name = nm;
    if (rep != nullptr) attachInstances({rep}, rep);
    setCategory(cat, 0);
    (void)id;
}

void HighOther::decode(Decoder& /*decoder*/) {}

}  // namespace pcode
}  // namespace ghidra
