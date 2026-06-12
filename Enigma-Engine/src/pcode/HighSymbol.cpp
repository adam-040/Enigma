/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighSymbol.cpp
/// \brief A symbol within the decompiler's model of a particular function.
#include "ghidra/HighSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MutabilitySettingsDefinition.h"
#include "ghidra/Encoder.h"
#include "ghidra/Decoder.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {

HighSymbol::HighSymbol(pcode::HighFunction* func)
    : type(nullptr), function(func), dtmanage(nullptr),
      category(-1), categoryIndex(-1),
      namelock(false), typelock(false), isThis(false), isHidden(false),
      id(0), highVariable(nullptr) {}

HighSymbol::HighSymbol(int64_t uniqueId, const std::string& nm, DataType* tp, pcode::HighFunction* func)
    : name(nm), type(tp), function(func), dtmanage(nullptr),
      category(-1), categoryIndex(-1),
      namelock(false), typelock(false), isThis(false), isHidden(false),
      id(uniqueId), highVariable(nullptr) {}

HighSymbol::HighSymbol(int64_t uniqueId, const std::string& nm, DataType* tp, bool tlock, bool nlock, void* manage)
    : name(nm), type(tp), function(nullptr), dtmanage(manage),
      category(-1), categoryIndex(-1),
      namelock(nlock), typelock(tlock), isThis(false), isHidden(false),
      id(uniqueId), highVariable(nullptr) {}

const Address& HighSymbol::getStorageAddress() const {
    static const Address empty;
    return empty;
}

int HighSymbol::getSize() const {
    if (!entryList.empty()) {
        return entryList[0]->getSize();
    }
    return 0;
}

const Address& HighSymbol::getPCAddress() const {
    if (!entryList.empty()) {
        return entryList[0]->getPCAdress();
    }
    static const Address empty;
    return empty;
}

int HighSymbol::getMutability() const {
    if (!entryList.empty()) {
        return entryList[0]->getMutability();
    }
    return MutabilitySettingsDefinition::NORMAL;
}

void HighSymbol::addMapEntry(SymbolEntry* entry) {
    if (entry == nullptr) return;
    entryList.push_back(entry);
}

SymbolEntry* HighSymbol::getFirstWholeMap() const {
    return entryList.empty() ? nullptr : entryList[0];
}

VariableStorage HighSymbol::getStorage() const {
    return entryList.empty() ? VariableStorage() : entryList[0]->getStorage();
}

void HighSymbol::encode(Encoder& encoder) const {
    encoder.openElement(ELEM_SYMBOL);
    encodeHeader(encoder);
    encoder.closeElement(ELEM_SYMBOL);
}

void HighSymbol::decode(Decoder& decoder) {
    int symel = decoder.openElement(ELEM_SYMBOL);
    (void)symel;
    decodeHeader(decoder);
    decoder.closeElement(symel);
}

void HighSymbol::encodeHeader(Encoder& encoder) const {
    if ((id >> 56) != (ID_BASE >> 56)) {
        encoder.writeUnsignedInteger(ATTRIB_ID, static_cast<uint64_t>(id));
    }
    encoder.writeString(ATTRIB_NAME, name);
    encoder.writeBool(ATTRIB_TYPELOCK, typelock);
    encoder.writeBool(ATTRIB_NAMELOCK, namelock);
    int mutability = getMutability();
    if (mutability == MutabilitySettingsDefinition::CONSTANT) {
        encoder.writeBool(ATTRIB_READONLY, true);
    } else if (mutability == MutabilitySettingsDefinition::VOLATILE) {
        encoder.writeBool(ATTRIB_VOLATILE, true);
    }
    if (isIsolated()) {
        encoder.writeBool(ATTRIB_MERGE, false);
    }
    if (isThis) {
        encoder.writeBool(ATTRIB_THISPTR, true);
    }
    if (isHidden) {
        encoder.writeBool(ATTRIB_HIDDENRETPARM, true);
    }
    encoder.writeSignedInteger(ATTRIB_CAT, category);
    if (categoryIndex >= 0) {
        encoder.writeUnsignedInteger(ATTRIB_INDEX, static_cast<uint64_t>(categoryIndex));
    }
}

void HighSymbol::decodeHeader(Decoder& decoder) {
    name.clear();
    id = 0;
    typelock = false;
    namelock = false;
    isThis = false;
    isHidden = false;
    categoryIndex = -1;
    category = -1;
    (void)decoder;
}

} // namespace ghidra
