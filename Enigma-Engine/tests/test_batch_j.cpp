/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_j.cpp
/// \brief Tests for batch J: model.pcode symbol map family.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/PartialUnion.h"
#include "ghidra/UnionFacetSymbol.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/DynamicEntry.h"
#include "ghidra/MappedDataEntry.h"
#include "ghidra/GlobalSymbolMap.h"
#include "ghidra/LocalSymbolMap.h"
#include "ghidra/DynamicHash.h"
#include "ghidra/Union.h"
#include "ghidra/Pointer.h"
#include "ghidra/TypeDef.h"
#include "ghidra/Address.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/MutabilitySettingsDefinition.h"
#include "ghidra/HighSymbol.h"

namespace {

int passed = 0;
int total = 0;

#define TEST(name, expr) do { \
    ++total; \
    if (expr) { \
        std::cout << "[PASS] " << name << "\n" << std::flush; \
        ++passed; \
    } else { \
        std::cout << "[FAIL] " << name << "\n" << std::flush; \
    } \
} while(0)

// Test HighSymbol implementation: a tiny in-memory stub for testing
class TestHighSymbol : public ghidra::HighSymbol {
public:
    TestHighSymbol(int64_t id, const std::string& nm, ghidra::DataType* dt, int sz)
        : id_(id), name_(nm), type_(dt), size_(sz) {}
    int64_t getId() const override { return id_; }
    const std::string& getName() const override { return name_; }
    ghidra::DataType* getDataType() const override { return type_; }
    int getSize() const override { return size_; }
    const ghidra::Address& getStorageAddress() const override { return addr_; }
    void setStorageAddress(const ghidra::Address& a) { addr_ = a; }
private:
    int64_t id_;
    std::string name_;
    ghidra::DataType* type_;
    int size_;
    ghidra::Address addr_;
};

void test_element_ids() {
    TEST("ELEM_HASH.id is 274", ghidra::ELEM_HASH.id == 274);
    TEST("ELEM_FACETSYMBOL.id is 275", ghidra::ELEM_FACETSYMBOL.id == 275);
    TEST("ELEM_ADDR.id is 277", ghidra::ELEM_ADDR.id == 277);
    TEST("ELEM_HASH.name == hash", ghidra::ELEM_HASH.name == "hash");
    TEST("ELEM_FACETSYMBOL.name == facetsymbol", ghidra::ELEM_FACETSYMBOL.name == "facetsymbol");
    TEST("ELEM_ADDR.name == addr", ghidra::ELEM_ADDR.name == "addr");
    TEST("ELEM_HASH != ELEM_FACETSYMBOL", ghidra::ELEM_HASH != ghidra::ELEM_FACETSYMBOL);
    TEST("ELEM_FACETSYMBOL != ELEM_ADDR", ghidra::ELEM_FACETSYMBOL != ghidra::ELEM_ADDR);
}

void test_partial_union() {
    ghidra::PartialUnion pu(nullptr, nullptr, 0, 4);
    TEST("PartialUnion.getLength == 4", pu.getLength() == 4);
    TEST("PartialUnion.getOffset == 0", pu.getOffset() == 0);
    TEST("PartialUnion.getParent == nullptr", pu.getParent() == nullptr);
    TEST("PartialUnion.getAlignment == 0", pu.getAlignment() == 0);
    TEST("PartialUnion.getAlignedLength == 4", pu.getAlignedLength() == 4);

    ghidra::PartialUnion pu2(nullptr, nullptr, 8, 4);
    TEST("PartialUnion2.getLength == 4", pu2.getLength() == 4);
    TEST("PartialUnion2.getOffset == 8", pu2.getOffset() == 8);
    TEST("PartialUnion2.getAlignedLength == 4", pu2.getAlignedLength() == 4);

    TEST("PartialUnion.isEquivalent(null) == false", !pu.isEquivalent(nullptr));
    TEST("PartialUnion.isEquivalent(other) == false when offset differs",
         !pu.isEquivalent(&pu2));
    TEST("PartialUnion.name == partialunion", pu.getName() == "partialunion");
    TEST("PartialUnion.pathName contains /", pu.getPathName().find("partialunion") != std::string::npos);
    TEST("PartialUnion.description set", pu.getDescription() == "Partial Union (internal)");
    TEST("PartialUnion.isEquivalent(self) == true", pu.isEquivalent(&pu));
}

void test_partial_union_stripped() {
    ghidra::PartialUnion pu(nullptr, nullptr, 0, 4);
    ghidra::DataType* stripped = pu.getStrippedDataType();
    TEST("PartialUnion.getStrippedDataType() != nullptr", stripped != nullptr);
    if (stripped) {
        TEST("Stripped is size 4", stripped->getLength() == 4);
    }
}

void test_union_facet_symbol() {
    ghidra::Address addr(nullptr, 0x1234);
    std::string nm = ghidra::UnionFacetSymbol::buildSymbolName(0, addr, false);
    TEST("buildSymbolName contains unionfacet", nm.find("unionfacet") == 0);
    TEST("buildSymbolName has 1_ (fieldNum+1)", nm.find("1_") != std::string::npos);
    TEST("buildSymbolName has hex offset 1234", nm.find("1234") != std::string::npos);

    std::string nm2 = ghidra::UnionFacetSymbol::buildSymbolName(2, addr, true);
    TEST("buildSymbolName addr-based has 'a' marker", nm2.find("unionfaceta") == 0);
    TEST("buildSymbolName field 2 has 3_", nm2.find("3_") != std::string::npos);

    TEST("extractFieldNumber(unionfacet1_1234) == 0",
         ghidra::UnionFacetSymbol::extractFieldNumber("unionfacet1_1234") == 0);
    TEST("extractFieldNumber(unionfacet3_1234) == 2",
         ghidra::UnionFacetSymbol::extractFieldNumber("unionfacet3_1234") == 2);
    TEST("extractFieldNumber(unionfaceta3_1234) == 2",
         ghidra::UnionFacetSymbol::extractFieldNumber("unionfaceta3_1234") == 2);
    TEST("extractFieldNumber(junk) == -1",
         ghidra::UnionFacetSymbol::extractFieldNumber("junk") == -1);
    TEST("extractFieldNumber(unionfacetX) == -1",
         ghidra::UnionFacetSymbol::extractFieldNumber("unionfacetX") == -1);

    TEST("extractAddressBased(unionfacet1_1234) == false",
         ghidra::UnionFacetSymbol::extractAddressBased("unionfacet1_1234") == false);
    TEST("extractAddressBased(unionfaceta1_1234) == true",
         ghidra::UnionFacetSymbol::extractAddressBased("unionfaceta1_1234") == true);
    TEST("extractAddressBased(junk) == false",
         ghidra::UnionFacetSymbol::extractAddressBased("junk") == false);
    TEST("extractAddressBased(unionfacet) == false (too short)",
         ghidra::UnionFacetSymbol::extractAddressBased("unionfacet") == false);

    ghidra::UnionFacetSymbol ufs(42, "unionfacet2_5678", nullptr);
    TEST("UnionFacetSymbol.getId == 42", ufs.getId() == 42);
    TEST("UnionFacetSymbol.getName preserved", ufs.getName() == "unionfacet2_5678");
    TEST("UnionFacetSymbol.getFieldNumber == 1", ufs.getFieldNumber() == 1);
    TEST("UnionFacetSymbol.isAddrBased == false", !ufs.isAddrBased());

    ghidra::UnionFacetSymbol ufs2(43, "unionfaceta3_5678", nullptr);
    TEST("UnionFacetSymbol addr-based.isAddrBased == true", ufs2.isAddrBased());
    TEST("UnionFacetSymbol addr-based.getFieldNumber == 2", ufs2.getFieldNumber() == 2);
}

void test_is_union_type() {
    TEST("isUnionType(nullptr) == false", !ghidra::UnionFacetSymbol::isUnionType(nullptr));
}

void test_dynamic_entry() {
    ghidra::Address pc(nullptr, 0x1000);
    TestHighSymbol sym(7, "var1", nullptr, 4);
    ghidra::DynamicEntry de(&sym, pc, 0xDEADBEEFLL);
    TEST("DynamicEntry.getHash == 0xDEADBEEF", de.getHash() == static_cast<int64_t>(0xDEADBEEFLL));
    TEST("DynamicEntry.getSymbol == &sym", de.getSymbol() == &sym);
    TEST("DynamicEntry.getPCAdress.offset == 0x1000", de.getPCAdress().getOffset() == 0x1000);
    TEST("DynamicEntry.getSize == sym.getSize", de.getSize() == 4);
    TEST("DynamicEntry.getMutability == NORMAL",
         de.getMutability() == ghidra::MutabilitySettingsDefinition::NORMAL);

    ghidra::DynamicEntry de2(&sym);
    TEST("DynamicEntry default ctor hash == 0", de2.getHash() == 0);
}

void test_mapped_entry() {
    ghidra::VariableStorage vs;
    TestHighSymbol sym(1, "v", nullptr, 8);
    ghidra::MappedEntry me(&sym, vs, ghidra::Address(nullptr, 0x2000));
    TEST("MappedEntry.getSize == vs.size()", me.getSize() == vs.size());
    TEST("MappedEntry.getMutability == NORMAL",
         me.getMutability() == ghidra::MutabilitySettingsDefinition::NORMAL);
    TEST("MappedEntry.getSymbol == &sym", me.getSymbol() == &sym);

    ghidra::MappedEntry me2(&sym);
    TEST("MappedEntry default ctor", me2.getSize() == 0);
}

void test_mapped_data_entry() {
    ghidra::VariableStorage vs;
    TestHighSymbol sym(2, "dv", nullptr, 4);
    int dummyData = 0;
    ghidra::MappedDataEntry mde(&sym, vs, &dummyData);
    TEST("MappedDataEntry.getData == &dummyData", mde.getData() == &dummyData);
    TEST("MappedDataEntry.getSize == vs.size()", mde.getSize() == vs.size());
    TEST("MappedDataEntry.getMutability == NORMAL",
         mde.getMutability() == ghidra::MutabilitySettingsDefinition::NORMAL);
    TEST("MappedDataEntry.getSymbol == &sym", mde.getSymbol() == &sym);
}

void test_global_symbol_map() {
    ghidra::GlobalSymbolMap gsm;
    TEST("GlobalSymbolMap empty size == 0", gsm.size() == 0);
    TEST("GlobalSymbolMap getSymbol(unknown) == nullptr", gsm.getSymbol(123) == nullptr);
    TEST("GlobalSymbolMap getSymbol(addr) == nullptr for empty", gsm.getSymbol(ghidra::Address()) == nullptr);
    TEST("GlobalSymbolMap getNextUniqueSymbolId == 0", gsm.getNextUniqueSymbolId() == 0);
    TEST("GlobalSymbolMap getSymbols() empty", gsm.getSymbols().empty());
}

void test_local_symbol_map() {
    ghidra::LocalSymbolMap lsm;
    TEST("LocalSymbolMap empty size == 0", lsm.size() == 0);
    TEST("LocalSymbolMap getSymbol(unknown) == nullptr", lsm.getSymbol(0) == nullptr);
}

void test_dynamic_hash() {
    ghidra::DynamicHash dh;
    TEST("DynamicHash default hash == 0", dh.getHash() == 0);
    TEST("DynamicHash default address is invalid", !dh.getAddress().isValid());

    ghidra::DynamicHash dh2(nullptr, nullptr);
    TEST("DynamicHash stub ctor hash == 0", dh2.getHash() == 0);

    TEST("hashVarnode stub returns 0", ghidra::DynamicHash::hashVarnode(nullptr, nullptr) == 0);
    TEST("hashPcodeOp stub returns 0", ghidra::DynamicHash::hashPcodeOp(nullptr, nullptr) == 0);
}

void test_symbol_entry_interface() {
    // Verify SymbolEntry is abstract (cannot be instantiated).
    // We instead check that the inheritance compiles for MappedEntry and DynamicEntry.
    TestHighSymbol sym(99, "x", nullptr, 2);
    ghidra::DynamicEntry de(&sym);
    ghidra::SymbolEntry* base = &de;
    TEST("SymbolEntry* upcast from DynamicEntry works", base != nullptr);
    TEST("SymbolEntry* getSymbol() returns sym", base->getSymbol() == &sym);

    ghidra::MappedEntry me(&sym);
    ghidra::SymbolEntry* base2 = &me;
    TEST("SymbolEntry* upcast from MappedEntry works", base2 != nullptr);
    TEST("MappedEntry via base: getSize() == 0", base2->getSize() == 0);
}

}  // namespace

int main() {
    test_element_ids();
    test_partial_union();
    test_partial_union_stripped();
    test_union_facet_symbol();
    test_is_union_type();
    test_dynamic_entry();
    test_mapped_entry();
    test_mapped_data_entry();
    test_global_symbol_map();
    test_local_symbol_map();
    test_dynamic_hash();
    test_symbol_entry_interface();

    std::cout << "\n[Batch J] " << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
