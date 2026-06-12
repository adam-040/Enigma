/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighConstant.cpp
/// \brief A constant that has been given a datatype.
#include "ghidra/pcode/HighConstant.h"
#include "ghidra/HighSymbol.h"
#include "ghidra/Varnode.h"
#include "ghidra/AbstractIntegerDataType.h"
#include "ghidra/DataType.h"

namespace ghidra {
namespace pcode {

HighConstant::HighConstant(HighFunction* func)
    : HighVariable(func), symbol(nullptr), value(0) {}

HighConstant::HighConstant(const std::string& nm, DataType* type, Varnode* vn,
                           const Address& pc, HighFunction* func)
    : HighVariable(nm, type, vn, std::vector<Varnode*>(), func), pcaddr(pc), symbol(nullptr), value(0) {}

HighConstant::HighConstant(int64_t id, const std::string& nm, Varnode* rep,
                           int cat, int64_t val, HighFunction* func)
    : HighVariable(func), symbol(nullptr), value(val) {
    name = nm;
    if (rep != nullptr) attachInstances({rep}, rep);
    setCategory(cat, 0);
    setReadOnly(true);
    (void)id;
}

int64_t HighConstant::getScalarValue() const {
    if (represent == nullptr) return value;
    return represent->getOffset();
}

void HighConstant::decode(Decoder& /*decoder*/) {}

}  // namespace pcode
}  // namespace ghidra
