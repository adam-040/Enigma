/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighGlobal.cpp
/// \brief All references (per function) to a single global variable.
#include "ghidra/pcode/HighGlobal.h"
#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

HighGlobal::HighGlobal(HighFunction* func) : HighVariable(func), symbol(nullptr) {}

HighGlobal::HighGlobal(DataType* tp, Varnode* vn, const std::vector<Varnode*>& inst,
                       const Address& pc, HighSymbol* sym)
    : HighVariable(sym ? sym->getName() : std::string(), tp, vn, inst,
                   sym ? sym->getHighFunction() : nullptr),
      addr(pc), symbol(sym) {}

HighGlobal::HighGlobal(int64_t id, const std::string& nm, Varnode* rep,
                       int cat, bool readonly, int64_t addrOffset, HighFunction* func)
    : HighVariable(func), symbol(nullptr) {
    name = nm;
    if (rep != nullptr) {
        addr = rep->getAddress();
        attachInstances({rep}, rep);
    } else {
        addr = Address(nullptr, addrOffset);
    }
    setCategory(cat, 0);
    setReadOnly(readonly);
    (void)id;
}

void HighGlobal::decode(Decoder& /*decoder*/) {}

}  // namespace pcode
}  // namespace ghidra
