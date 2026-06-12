/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighVariable.cpp
/// \brief High-level variable built out of Varnodes.
#include "ghidra/pcode/HighVariable.h"
#include "ghidra/Varnode.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"
#include "ghidra/ElementId.h"

namespace ghidra {
namespace pcode {

HighVariable::HighVariable(HighFunction* func)
    : type(nullptr), represent(nullptr), offset(-1), function(func),
      instanceNum(0), readonly(false), volatile_(false), hiddenReturn(false),
      category(-1), categoryIndex(-1) {}

HighVariable::HighVariable(const std::string& nm, DataType* tp, Varnode* rep,
                           const std::vector<Varnode*>& inst, HighFunction* func)
    : name(nm), type(tp), offset(-1), function(func),
      instanceNum(0), readonly(false), volatile_(false), hiddenReturn(false),
      category(-1), categoryIndex(-1) {
    attachInstances(inst, rep);
}

int HighVariable::getSize() const {
    return represent ? represent->getSize() : 0;
}

void HighVariable::attachInstances(const std::vector<Varnode*>& inst, Varnode* rep) {
    represent = rep;
    if (inst.empty()) {
        instances.clear();
        if (rep) instances.push_back(rep);
    } else {
        instances = inst;
    }
    setHighOnInstances();
}

void HighVariable::setHighOnInstances() {
    for (size_t i = 0; i < instances.size(); ++i) {
        (void)instances[i];
    }
}

bool HighVariable::requiresDynamicStorage() const {
    if (represent == nullptr) return false;
    if (represent->isUnique()) return true;
    if (represent->getAddress().isStackAddress() && !represent->isAddrTied()) return true;
    return false;
}

void HighVariable::encode(Encoder& /*encoder*/) const {}

void HighVariable::decodeInstances(Decoder& /*decoder*/) {}

}  // namespace pcode
}  // namespace ghidra
