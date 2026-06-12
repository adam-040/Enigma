/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeSymbol.h
/// \brief A symbol representing a DataType.
/// Translated from: ghidra.program.model.pcode.DataTypeSymbol
#pragma once

#include "ghidra/HighSymbol.h"
#include "ghidra/Address.h"
#include "ghidra/TypeDef.h"
#include <string>

namespace ghidra {

class DataType;
class TypeDef;
namespace pcode {
class HighFunction;
}
using PcodeHighFunction = pcode::HighFunction;

class DataTypeSymbol : public HighSymbol {
public:
    DataTypeSymbol() : HighSymbol() {}

    DataTypeSymbol(int64_t uniqueId, const std::string& nm, TypeDef* type,
                   pcode::HighFunction* func, const Address& addr, int64_t hash);

    TypeDef* getType() const { return dt; }
    int getSize() const override;
    int getStorageSize() const { return storageSize; }
    const Address& getAddress() const { return addr; }
    int64_t getHash() const { return hash; }

    void encode(Encoder& encoder) const override;
    void decode(Decoder& decoder) override;
    void saveXml(Encoder& encoder, int sourceType) const;

private:
    TypeDef* dt;
    int storageSize;
    Address addr;
    int64_t hash;
};

}  // namespace ghidra
