/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighCodeSymbol.cpp
/// \brief A global symbol as part of the decompiler's model of a function.
#include "ghidra/pcode/HighCodeSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/MappedDataEntry.h"
#include "ghidra/Decoder.h"
#include "ghidra/VariableStorage.h"

namespace ghidra {
namespace pcode {

HighCodeSymbol::HighCodeSymbol(void* sym, HighFunction* func)
    : HighSymbol(0, std::string(), nullptr, func), backingCodeSymbol(sym), backingData(nullptr) {
    setNameLock(true);
    setTypeLock(true);
    addMapEntry(new MappedEntry(this, VariableStorage::UNASSIGNED_STORAGE, Address()));
}

HighCodeSymbol::HighCodeSymbol(int64_t id, const Address& addr, DataType* dataType, int sz, HighFunction* func)
    : HighSymbol(id, std::string(), dataType, func), backingCodeSymbol(nullptr), backingData(nullptr) {
    (void)addr; (void)sz;
    setNameLock(true);
    setTypeLock(true);
    addMapEntry(new MappedEntry(this, VariableStorage::UNASSIGNED_STORAGE, Address()));
}

HighCodeSymbol::HighCodeSymbol(int64_t id, const std::string& nm, void* data, void* dtmanage)
    : HighSymbol(id, nm, nullptr, true, true, dtmanage),
      backingCodeSymbol(nullptr), backingData(data) {
    addMapEntry(new MappedDataEntry(this, VariableStorage::UNASSIGNED_STORAGE, data));
}

void HighCodeSymbol::decode(Decoder& decoder) {
    HighSymbol::decode(decoder);
    backingCodeSymbol = nullptr;
}

}  // namespace pcode
}  // namespace ghidra
