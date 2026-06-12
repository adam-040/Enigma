/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighSymbol.h
/// \brief A symbol within the decompiler's model of a particular function.
/// Translated from: ghidra.program.model.pcode.HighSymbol
#pragma once

#include <ghidra/DataType.h>
#include <ghidra/Address.h>
#include <ghidra/VariableStorage.h>
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {
namespace pcode {
class HighFunction;
}  // namespace pcode
}  // namespace ghidra

namespace ghidra {

class SymbolEntry;
class HighVariable;
class Encoder;
class Decoder;

/**
 * A symbol within the decompiler's model of a particular function. The symbol has a
 * name, a data-type, and other properties. The symbol is mapped to one or more
 * storage locations by attaching a SymbolEntry for each mapping.
 */
class HighSymbol {
public:
    static constexpr int64_t ID_BASE = 0x4000000000000000LL;

    /// Constructor for use with restoreXML
    explicit HighSymbol(pcode::HighFunction* func = nullptr);

    /// Basic symbol constructor
    HighSymbol(int64_t uniqueId, const std::string& nm, DataType* tp, pcode::HighFunction* func);

    /// Standalone symbol constructor (not attached to a HighFunction)
    HighSymbol(int64_t uniqueId, const std::string& nm, DataType* tp, bool tlock, bool nlock, void* dtmanage);

    virtual ~HighSymbol() = default;

    virtual int64_t getId() const { return id; }
    virtual const std::string& getName() const { return name; }
    void setName(const std::string& nm) { name = nm; }
    virtual DataType* getDataType() const { return type; }
    void setDataTypeRaw(DataType* dt) { type = dt; }
    pcode::HighFunction* getHighFunction() const { return function; }
    virtual const Address& getStorageAddress() const;

    virtual int getSize() const;
    const Address& getPCAddress() const;

    void setCategory(int cat, int index) { category = cat; categoryIndex = index; }
    int getCategory() const { return category; }
    int getCategoryIndex() const { return categoryIndex; }
    bool isParameter() const { return category == 0; }

    void setTypeLock(bool lock) { typelock = lock; }
    void setNameLock(bool lock) { namelock = lock; }
    bool isTypeLocked() const { return typelock; }
    bool isNameLocked() const { return namelock; }
    bool isIsolated() const { return typelock; }
    bool isThisPointer() const { return isThis; }
    void setThisPointer(bool t) { isThis = t; }
    bool isHiddenReturn() const { return isHidden; }
    void setHiddenReturn(bool h) { isHidden = h; }

    virtual bool isGlobal() const { return false; }
    virtual int getMutability() const;

    /// Add a mapping entry to this symbol
    void addMapEntry(SymbolEntry* entry);
    const std::vector<SymbolEntry*>& getEntryList() const { return entryList; }
    SymbolEntry* getFirstWholeMap() const;

    /// Storage of the first mapping
    VariableStorage getStorage() const;

    void setHighVariable(HighVariable* high) { highVariable = high; }
    HighVariable* getHighVariable() const { return highVariable; }

    virtual void encode(Encoder& encoder) const;
    virtual void decode(Decoder& decoder);

protected:
    void encodeHeader(Encoder& encoder) const;
    void decodeHeader(Decoder& decoder);

    std::string name;
    DataType* type;
    pcode::HighFunction* function;
    void* dtmanage;
    int category;
    int categoryIndex;
    bool namelock;
    bool typelock;
    bool isThis;
    bool isHidden;
    int64_t id;
    std::vector<SymbolEntry*> entryList;
    HighVariable* highVariable;
};

} // namespace ghidra
