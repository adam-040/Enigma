/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file UnionFacetSymbol.h
/// \brief HighSymbol directing the decompiler to use a specific field of a union.
/// Translated from: ghidra.program.model.pcode.UnionFacetSymbol
#pragma once

#include <ghidra/HighSymbol.h>
#include <ghidra/DataType.h>
#include <ghidra/Address.h>
#include <ghidra/Encoder.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>
#include <cstdint>
#include <string>

namespace ghidra {

/**
 * A specialized HighSymbol that directs the decompiler to use a specific field of a union
 * when interpreting a particular PcodeOp that accesses a Varnode whose data-type involves
 * the union. Stored as a dynamic variable annotation. The data-type must either be the
 * union itself or a pointer to the union.
 */
class UnionFacetSymbol : public HighSymbol {
public:
    static inline const std::string BASENAME = "unionfacet";

    UnionFacetSymbol(int64_t uniqueId, const std::string& nm, DataType* dt);

    void encode(Encoder& encoder) const;

    int64_t getId() const override { return id; }
    const std::string& getName() const override { return name; }
    DataType* getDataType() const override { return type; }
    int getSize() const override;
    const Address& getStorageAddress() const override { return storageAddr; }

    static std::string buildSymbolName(int fldNum, const Address& addr, bool isAddr);

    /// @return the field number encoded in the symbol name, or -1 on parse failure
    static int extractFieldNumber(const std::string& nm);

    /// @return true if the facet is address based (encoded in name)
    static bool extractAddressBased(const std::string& nm);

    /// @return true if the given data-type is a Union or pointer-to-Union
    static bool isUnionType(const DataType* dt);

    int getFieldNumber() const { return fieldNumber; }
    bool isAddrBased() const { return isAddrBased_; }

private:
    int64_t id;
    std::string name;
    DataType* type;
    Address storageAddr;
    int fieldNumber;
    bool isAddrBased_;
};

} // namespace ghidra
