/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file JumpTable.h
/// \brief JumpTable found as part of the decompilation of a function.
/// Translated from: ghidra.program.model.pcode.JumpTable
#pragma once

#include <ghidra/Address.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class Encoder;
class Decoder;

namespace pcode {

/**
 * JumpTable: decompiler-discovered switch/jump-table structure.
 */
class JumpTable {
public:
    /// Description of a table being loaded from memory.
    class LoadTable {
    public:
        LoadTable() : addr(), size(0), num(0) {}

        const Address& getAddress() const { return addr; }
        int getSize() const { return size; }
        int getNum() const { return num; }

        void decode(Decoder& decoder);

    private:
        Address addr;
        int size;
        int num;
    };

    /// A user-supplied set of jump destinations that overrides a derived table.
    class BasicOverride {
    public:
        BasicOverride() = default;
        explicit BasicOverride(const std::vector<Address>& dlist) : destlist(dlist) {}

        const std::vector<Address>& getDestinations() const { return destlist; }

        void encode(Encoder& encoder) const;

    private:
        std::vector<Address> destlist;
    };

    JumpTable();
    JumpTable(const Address& addr, const std::vector<Address>& destlist,
              bool override, int format);

    bool isEmpty() const { return addressTable.empty(); }

    void decode(Decoder& decoder);
    void encode(Encoder& encoder) const;

    const Address& getSwitchAddress() const { return opAddress; }
    const std::vector<Address>& getCases() const { return addressTable; }
    const std::vector<int>& getLabelValues() const { return labelTable; }
    const std::vector<LoadTable>& getLoadTables() const { return loadTable; }
    int getDisplayFormat() const { return displayFormat; }

    void setSwitchAddress(const Address& a) { opAddress = a; }
    void setDisplayFormat(int f) { displayFormat = f; }

private:
    Address opAddress;
    std::vector<Address> addressTable;
    std::vector<int> labelTable;
    std::vector<LoadTable> loadTable;
    std::unique_ptr<BasicOverride> override;
    int displayFormat;
};

}  // namespace pcode
}  // namespace ghidra
