/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighVariable.h
/// \brief High-level variable (as in a high-level language like C/C++) built out of Varnodes.
/// Translated from: ghidra.program.model.pcode.HighVariable
#pragma once

#include <ghidra/Address.h>
#include <ghidra/DataType.h>
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {
namespace pcode {
class HighFunction;
}  // namespace pcode
}  // namespace ghidra

namespace ghidra {

class Varnode;
class VarnodeAST;
class HighSymbol;
class Decoder;
class Encoder;

namespace pcode {

/**
 * A High-level variable built out of Varnodes (low-level variables). This is a base class.
 */
class HighVariable {
public:
    HighVariable(HighFunction* func);
    HighVariable(const std::string& nm, DataType* tp, Varnode* rep,
                 const std::vector<Varnode*>& inst, HighFunction* func);

    virtual ~HighVariable() = default;

    HighFunction* getHighFunction() const { return function; }
    const std::string& getName() const { return name; }
    void setName(const std::string& nm) { name = nm; }
    int getSize() const;
    DataType* getDataType() const { return type; }
    void setDataType(DataType* tp) { type = tp; }
    void setDataTypeRaw(DataType* tp) { type = tp; }
    Varnode* getRepresentative() const { return represent; }
    const std::vector<Varnode*>& getInstances() const { return instances; }

    /// @return the HighSymbol associated with this HighVariable (subclass-specific)
    virtual HighSymbol* getSymbol() const = 0;

    int32_t getOffset() const { return offset; }
    void setOffset(int32_t off) { offset = off; }

    int getInstanceNumber() const { return instanceNum; }
    void setInstanceNumber(int n) { instanceNum = n; }

    bool isReadOnly() const { return readonly; }
    void setReadOnly(bool r) { readonly = r; }
    bool isVolatile() const { return volatile_; }
    void setVolatile(bool v) { volatile_ = v; }
    bool isWritable() const { return !readonly; }

    virtual bool isParameter() const { return false; }
    virtual bool isConstant() const { return false; }
    virtual bool isGlobal() const { return false; }
    virtual bool isHiddenReturn() const { return hiddenReturn; }
    void setHiddenReturnParam(bool h) { hiddenReturn = h; }

    int getCategory() const { return category; }
    int getCategoryIndex() const { return categoryIndex; }
    void setCategory(int cat, int index) { category = cat; categoryIndex = index; }

    void attachInstances(const std::vector<Varnode*>& inst, Varnode* rep);

    bool requiresDynamicStorage() const;

    /// Decode this HighVariable from a <high> element
    virtual void decode(Decoder& decoder) = 0;

    /// Encode this HighVariable to a <high> element
    virtual void encode(Encoder& encoder) const;

protected:
    void setHighOnInstances();
    void decodeInstances(Decoder& decoder);

    std::string name;
    DataType* type;
    Varnode* represent;
    std::vector<Varnode*> instances;
    int32_t offset;
    HighFunction* function;
    int instanceNum;
    bool readonly;
    bool volatile_;
    bool hiddenReturn;
    int category;
    int categoryIndex;
};

}  // namespace pcode
}  // namespace ghidra
