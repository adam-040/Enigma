/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_t.cpp
/// \brief Tests for Batch T: Structure, Union, Enum, Typedef, Composite data types
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/CompositeDataTypeImpl.h>
#include <ghidra/CompositeInternal.h>
#include <ghidra/CompositeAlignmentHelper.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/StandAloneDataTypeManager.h>
#include <ghidra/BitFieldDataType.h>
#include <iostream>
#include <vector>
#include <set>
#include <memory>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// ---- StructureDataType tests ----

void test_struct_basic() {
    StructureDataType s("TestStruct", 0);
    TEST("struct.name", s.getName() == "TestStruct");
    TEST("struct.length", s.getLength() == 1);
    TEST("struct.numComps", s.getNumComponents() == 0);
    TEST("struct.numDefined", s.getNumDefinedComponents() == 0);
    TEST("struct.isZeroLength", s.isZeroLength());
    TEST("struct.mnemonic", s.getMnemonic(nullptr) == s.getName());
    TEST("struct.labelPrefix", s.getDefaultLabelPrefix() == "TestStruct");
}

void test_struct_add_bytes() {
    StructureDataType s("AddBytes", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    TEST("struct.add.bytes.numComps", s.getNumComponents() == 2);
    TEST("struct.add.bytes.numDef", s.getNumDefinedComponents() == 2);
    TEST("struct.add.bytes.length", s.getLength() == 2);
    DataTypeComponent* c0 = s.getComponent(0);
    TEST("struct.add.bytes.c0.dt", c0 != nullptr && c0->getDataType() == &ByteDataType::dataType());
    TEST("struct.add.bytes.c0.len", c0 != nullptr && c0->getLength() == 1);
    TEST("struct.add.bytes.c0.ord", c0 != nullptr && c0->getOrdinal() == 0);
    DataTypeComponent* c1 = s.getComponent(1);
    TEST("struct.add.bytes.c1.ord", c1 != nullptr && c1->getOrdinal() == 1);
}

void test_struct_add_named() {
    StructureDataType s("Named", 0);
    s.add(&IntegerDataType::dataType(), 4, "myInt", "an integer field");
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.named.found", c != nullptr);
    TEST("struct.named.name", c->getFieldName() == "myInt");
    TEST("struct.named.comment", c->getComment() == "an integer field");
    TEST("struct.named.len", c->getLength() == 4);
}

void test_struct_add_with_length() {
    StructureDataType s("WithLen", 0);
    s.add(&ByteDataType::dataType(), 2);
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.add.wlen.len", c != nullptr && c->getLength() == 2);
    TEST("struct.add.wlen.dt", c != nullptr && c->getDataType() == &ByteDataType::dataType());
}

void test_struct_insert() {
    StructureDataType s("InsertTest", 0);
    s.add(&ByteDataType::dataType());
    s.insert(0, &IntegerDataType::dataType(), 4);
    TEST("struct.insert.num", s.getNumComponents() == 2);
    DataTypeComponent* c0 = s.getComponent(0);
    TEST("struct.insert.c0.dt", c0 != nullptr && c0->getDataType() == &IntegerDataType::dataType());
    TEST("struct.insert.c0.len", c0 != nullptr && c0->getLength() == 4);
    DataTypeComponent* c1 = s.getComponent(1);
    TEST("struct.insert.c1.dt", c1 != nullptr && c1->getDataType() == &ByteDataType::dataType());
    TEST("struct.insert.c1.ord", c1 != nullptr && c1->getOrdinal() == 1);
}

void test_struct_insert_at_offset() {
    StructureDataType s("InsertOff", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.insertAtOffset(1, &IntegerDataType::dataType(), 4);
    TEST("struct.insertOff.num", s.getNumComponents() == 3);
    DataTypeComponent* c1 = s.getComponent(1);
    TEST("struct.insertOff.c1.dt", c1 != nullptr && c1->getDataType() == &IntegerDataType::dataType());
    TEST("struct.insertOff.c1.offset", c1 != nullptr && c1->getOffset() == 1);
}

void test_struct_delete_component() {
    StructureDataType s("DelComp", 0);
    s.add(&ByteDataType::dataType());
    s.add(&IntegerDataType::dataType(), 4);
    s.deleteComponent(0);
    TEST("struct.del.num", s.getNumComponents() == 1);
    DataTypeComponent* c0 = s.getComponent(0);
    TEST("struct.del.c0.dt", c0 != nullptr && c0->getDataType() == &IntegerDataType::dataType());
}

void test_struct_delete_all() {
    StructureDataType s("DelAll", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.deleteAll();
    TEST("struct.delAll.num", s.getNumComponents() == 0);
    TEST("struct.delAll.len", s.getLength() == 1);
}

void test_struct_clear() {
    StructureDataType s("ClearTest", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.clearAtOffset(0);
    TEST("struct.clear.num", s.getNumComponents() == 1);
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.clear.c0.exists", c != nullptr);
    TEST("struct.clear.c0.offset", c != nullptr && c->getOffset() == 0);
}

void test_struct_replace() {
    StructureDataType s("Replace", 0);
    s.add(&ByteDataType::dataType());
    s.replace(0, &IntegerDataType::dataType(), 4);
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.replace.dt", c != nullptr && c->getDataType() == &IntegerDataType::dataType());
    TEST("struct.replace.len", c != nullptr && c->getLength() == 4);
}

void test_struct_get_components() {
    StructureDataType s("GetComps", 0);
    s.add(&ByteDataType::dataType());
    s.add(&WordDataType::dataType(), 2);
    s.add(&DWordDataType::dataType(), 4);
    auto comps = s.getComponents();
    TEST("struct.getComps.size", comps.size() == 3);
    auto defined = s.getDefinedComponents();
    TEST("struct.defComps.size", defined.size() == 3);
}

void test_struct_is_equivalent() {
    StructureDataType s1("EqStruct", 0);
    s1.add(&ByteDataType::dataType());
    StructureDataType s2("EqStruct", 0);
    s2.add(&ByteDataType::dataType());
    TEST("struct.eq.same", s1.isEquivalent(&s2));
    StructureDataType s3("EqDiff", 0);
    s3.add(&IntegerDataType::dataType(), 4);
    TEST("struct.eq.diff", s1.isEquivalent(&s3) == false);
}

void test_struct_clone() {
    StructureDataType s("CloneSrc", 0);
    s.add(&ByteDataType::dataType());
    s.add(&WordDataType::dataType(), 2);
    StandAloneDataTypeManager mgr("test");
    Structure* cloned = s.clone(&mgr);
    TEST("struct.clone.type", cloned != nullptr);
    TEST("struct.clone.name", cloned->getName() == "CloneSrc");
    TEST("struct.clone.numComps", cloned->getNumComponents() == 2);
    TEST("struct.clone.len", cloned->getLength() == 3);
    delete cloned;
}

void test_struct_copy() {
    StructureDataType s("CopySrc", 0);
    s.add(&ByteDataType::dataType());
    StandAloneDataTypeManager mgr("test");
    DataType* copied = s.copy(&mgr);
    TEST("struct.copy.type", copied != nullptr);
    TEST("struct.copy.name", copied->getName() == "CopySrc");
    TEST("struct.copy.len", copied->getLength() == 1);
    delete copied;
}

void test_struct_grow() {
    StructureDataType s("Grow", 0);
    s.add(&ByteDataType::dataType());
    s.growStructure(4);
    TEST("struct.grow.len", s.getLength() == 5);
    TEST("struct.grow.num", s.getNumComponents() == 5);
}

void test_struct_set_length() {
    StructureDataType s("SetLen", 0);
    s.setLength(16);
    TEST("struct.setLen.len", s.getLength() == 16);
}

void test_struct_get_defined_components() {
    StructureDataType s("DefComps", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    auto defined = s.getDefinedComponents();
    TEST("struct.defComps.size", defined.size() == 2);
}

void test_struct_get_component_containing() {
    StructureDataType s("Contain", 0);
    s.add(&IntegerDataType::dataType(), 4);
    DataTypeComponent* c = s.getComponentContaining(2);
    TEST("struct.contain.2", c != nullptr && c->getOrdinal() == 0);
    c = s.getComponentContaining(5);
    TEST("struct.contain.5", c == nullptr);
}

void test_struct_delete_components_set() {
    StructureDataType s("DelSet", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.deleteComponents({0, 2});
    TEST("struct.delSet.num", s.getNumComponents() == 1);
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.delSet.c0.exists", c != nullptr);
    TEST("struct.delSet.c0.ord", c != nullptr && c->getOrdinal() == 0);
}

void test_struct_add_bitfield() {
    StructureDataType s("BitField", 0);
    DataTypeComponent* bfc = s.addBitField(&ByteDataType::dataType(), 3, "bf", "3-bit field");
    TEST("struct.bf.created", bfc != nullptr);
    TEST("struct.bf.bitFieldComp", bfc != nullptr && bfc->isBitFieldComponent());
    TEST("struct.bf.name", bfc != nullptr && bfc->getFieldName() == "bf");
    DataType* bfdt = bfc->getDataType();
    BitFieldDataType* bft = dynamic_cast<BitFieldDataType*>(bfdt);
    TEST("struct.bf.bitFieldType", bft != nullptr);
    TEST("struct.bf.bitSize", bft != nullptr && bft->getBitSize() == 3);
}

void test_struct_insert_bitfield() {
    StructureDataType s("InsBF", 0);
    s.add(&ByteDataType::dataType());
    DataTypeComponent* bfc = s.insertBitField(0, 4, 2, &ByteDataType::dataType(), 3,
                                               "insbf", "inserted bitfield");
    TEST("struct.insBF.created", bfc != nullptr);
    TEST("struct.insBF.ordinal", bfc != nullptr && bfc->getOrdinal() == 0);
    TEST("struct.insBF.offset", bfc != nullptr && bfc->getOffset() == 0);
}

void test_struct_find_component() {
    StructureDataType s("FindComp", 0);
    s.add(&ByteDataType::dataType(), "fieldA", "first field");
    s.add(&ByteDataType::dataType(), "fieldB", "second field");
    DataTypeComponent* c = s.findComponent("fieldB");
    TEST("struct.find.fieldB", c != nullptr);
    TEST("struct.find.fieldB.comment", c != nullptr && c->getComment() == "second field");
    c = s.findComponent("nonexistent");
    TEST("struct.find.missing", c == nullptr);
}

void test_struct_delete_at_offset() {
    StructureDataType s("DelOff", 0);
    s.add(&ByteDataType::dataType());
    s.add(&IntegerDataType::dataType(), 4);
    s.deleteAtOffset(0);
    TEST("struct.delOff.num", s.getNumComponents() == 1);
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.delOff.c0.dt", c != nullptr && c->getDataType() == &IntegerDataType::dataType());
}

void test_struct_clear_component() {
    StructureDataType s("ClearComp", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.clearComponent(1);
    TEST("struct.clearComp.num", s.getNumComponents() == 1);
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.clearComp.c0.ord", c != nullptr && c->getOrdinal() == 0);
}

void test_struct_insert_named() {
    StructureDataType s("InsNamed", 0);
    s.add(&ByteDataType::dataType());
    s.insert(0, &IntegerDataType::dataType(), 4, "inserted", "inserted field");
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.insNamed.name", c != nullptr && c->getFieldName() == "inserted");
    TEST("struct.insNamed.comment", c != nullptr && c->getComment() == "inserted field");
}

void test_struct_replace_named() {
    StructureDataType s("RepNamed", 0);
    s.add(&ByteDataType::dataType());
    s.replace(0, &IntegerDataType::dataType(), 4, "replaced", "replaced field");
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.repNamed.name", c != nullptr && c->getFieldName() == "replaced");
    TEST("struct.repNamed.comment", c != nullptr && c->getComment() == "replaced field");
}

void test_struct_replace_at_offset() {
    StructureDataType s("RepOff", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.replaceAtOffset(0, &IntegerDataType::dataType(), 4, "repOff", "replaced at offset");
    DataTypeComponent* c = s.getComponent(0);
    TEST("struct.repOff.dt", c != nullptr && c->getDataType() == &IntegerDataType::dataType());
    TEST("struct.repOff.name", c != nullptr && c->getFieldName() == "repOff");
}

void test_struct_get_defined_component_at_or_after() {
    StructureDataType s("DefAtOrAfter", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    DataTypeComponent* c = s.getDefinedComponentAtOrAfterOffset(0);
    TEST("struct.defAtOrAfter.0", c != nullptr && c->getOrdinal() == 0);
    c = s.getDefinedComponentAtOrAfterOffset(5);
    TEST("struct.defAtOrAfter.5", c == nullptr);
}

void test_struct_get_data_type_at() {
    StructureDataType s("DTAt", 0);
    s.add(&ByteDataType::dataType());
    DataTypeComponent* c = s.getDataTypeAt(0);
    TEST("struct.dtAt.0", c != nullptr && c->getOrdinal() == 0);
    c = s.getDataTypeAt(1);
    TEST("struct.dtAt.1", c == nullptr);
}

void test_struct_repack() {
    StructureDataType s("Repack", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.repack();
    TEST("struct.repack.ok", true);
}

void test_struct_multiple_adds() {
    StructureDataType s("MultiAdd", 0);
    s.add(&ByteDataType::dataType());
    s.add(&WordDataType::dataType(), 2);
    s.add(&DWordDataType::dataType(), 4);
    s.add(&FloatDataType::dataType(), 4);
    TEST("struct.multi.num", s.getNumComponents() == 4);
    TEST("struct.multi.len", s.getLength() == 11);
}

void test_struct_category_path() {
    CategoryPath cat("/root/sub");
    StructureDataType s(cat, "CatStruct", 0);
    TEST("struct.catPath.path", s.getCategoryPath().getPath() == "/root/sub");
    TEST("struct.catPath.name", s.getName() == "CatStruct");
}

void test_struct_insert_at_offset_named() {
    StructureDataType s("InsOffNamed", 0);
    s.add(&ByteDataType::dataType());
    s.add(&ByteDataType::dataType());
    s.insertAtOffset(1, &IntegerDataType::dataType(), 4, "insOffNamed", "insert at offset");
    DataTypeComponent* c = s.getComponent(1);
    TEST("struct.insOffNamed.name", c != nullptr && c->getFieldName() == "insOffNamed");
    TEST("struct.insOffNamed.comment", c != nullptr && c->getComment() == "insert at offset");
    TEST("struct.insOffNamed.offset", c != nullptr && c->getOffset() == 1);
}

// ---- UnionDataType tests ----

void test_union_basic() {
    UnionDataType u("TestUnion");
    TEST("union.name", u.getName() == "TestUnion");
    TEST("union.length", u.getLength() == 1);
    TEST("union.numComps", u.getNumComponents() == 0);
    TEST("union.mnemonic", u.getMnemonic(nullptr) == u.getName());
    TEST("union.labelPrefix", u.getDefaultLabelPrefix() == "UNION_TestUnion");
}

void test_union_add() {
    UnionDataType u("AddUnion");
    u.add(&ByteDataType::dataType());
    u.add(&IntegerDataType::dataType(), 4);
    TEST("union.add.num", u.getNumComponents() == 2);
    TEST("union.add.len", u.getLength() == 4);
    DataTypeComponent* c0 = u.getComponent(0);
    TEST("union.add.c0.offset", c0 != nullptr && c0->getOffset() == 0);
}

void test_union_add_named() {
    UnionDataType u("NamedUnion");
    u.add(&ByteDataType::dataType(), "byteField", "a byte");
    u.add(&IntegerDataType::dataType(), 4, "intField", "an int");
    TEST("union.named.num", u.getNumComponents() == 2);
    DataTypeComponent* c = u.getComponent(0);
    TEST("union.named.c0.name", c != nullptr && c->getFieldName() == "byteField");
    c = u.getComponent(1);
    TEST("union.named.c1.name", c != nullptr && c->getFieldName() == "intField");
}

void test_union_insert() {
    UnionDataType u("InsUnion");
    u.add(&ByteDataType::dataType());
    u.insert(0, &IntegerDataType::dataType(), 4);
    TEST("union.ins.num", u.getNumComponents() == 2);
    DataTypeComponent* c0 = u.getComponent(0);
    TEST("union.ins.c0.dt", c0 != nullptr && c0->getDataType() == &ByteDataType::dataType());
    DataTypeComponent* c1 = u.getComponent(1);
    TEST("union.ins.c1.dt", c1 != nullptr && c1->getDataType() == &IntegerDataType::dataType());
}

void test_union_delete() {
    UnionDataType u("DelUnion");
    u.add(&ByteDataType::dataType());
    u.add(&IntegerDataType::dataType(), 4);
    u.deleteComponent(0);
    TEST("union.del.num", u.getNumComponents() == 1);
    DataTypeComponent* c = u.getComponent(0);
    TEST("union.del.c0.dt", c != nullptr && c->getDataType() == &IntegerDataType::dataType());
}

void test_union_delete_set() {
    UnionDataType u("DelSetUnion");
    u.add(&ByteDataType::dataType());
    u.add(&ByteDataType::dataType());
    u.add(&ByteDataType::dataType());
    u.deleteComponents({0, 2});
    TEST("union.delSet.num", u.getNumComponents() == 1);
}

void test_union_repack() {
    UnionDataType u("RepackUnion");
    u.add(&ByteDataType::dataType());
    u.add(&IntegerDataType::dataType(), 4);
    u.repack();
    TEST("union.repack.len", u.getLength() == 4);
}

void test_union_clone() {
    UnionDataType u("CloneUnion");
    u.add(&ByteDataType::dataType());
    StandAloneDataTypeManager mgr("test");
    DataType* cloned = u.clone(&mgr);
    TEST("union.clone.name", cloned->getName() == "CloneUnion");
    UnionDataType* uCloned = dynamic_cast<UnionDataType*>(cloned);
    TEST("union.clone.type", uCloned != nullptr);
    TEST("union.clone.num", uCloned != nullptr && uCloned->getNumComponents() == 1);
    delete cloned;
}

void test_union_copy() {
    UnionDataType u("CopyUnion");
    u.add(&ByteDataType::dataType());
    StandAloneDataTypeManager mgr("test");
    DataType* copied = u.copy(&mgr);
    TEST("union.copy.name", copied->getName() == "CopyUnion");
    delete copied;
}

void test_union_is_equivalent() {
    UnionDataType u1("SameUnionEq");
    u1.add(&ByteDataType::dataType());
    UnionDataType u2("SameUnionEq");
    u2.add(&ByteDataType::dataType());
    TEST("union.eq.same", u1.isEquivalent(&u2));
    UnionDataType u3("DiffUnionEq");
    u3.add(&IntegerDataType::dataType(), 4);
    TEST("union.eq.diff", u1.isEquivalent(&u3) == false);
}

void test_union_get_components() {
    UnionDataType u("GetCompsUnion");
    u.add(&ByteDataType::dataType());
    u.add(&IntegerDataType::dataType(), 4);
    auto comps = u.getComponents();
    TEST("union.getComps.size", comps.size() == 2);
    auto defined = u.getDefinedComponents();
    TEST("union.defComps.size", defined.size() == 2);
}

void test_union_find_component() {
    UnionDataType u("FindUnion");
    u.add(&ByteDataType::dataType(), "fieldX", "x field");
    u.add(&IntegerDataType::dataType(), 4, "fieldY", "y field");
    DataTypeComponent* c = u.findComponent("fieldY");
    TEST("union.find.fieldY", c != nullptr);
    TEST("union.find.fieldY.comment", c != nullptr && c->getComment() == "y field");
    c = u.findComponent("nope");
    TEST("union.find.missing", c == nullptr);
}

void test_union_zero_length() {
    UnionDataType u("ZeroUnion");
    TEST("union.zero.isZero", u.isZeroLength());
    u.add(&ByteDataType::dataType());
    TEST("union.zero.nonZero", u.isZeroLength() == false);
}

void test_union_multiple_types() {
    UnionDataType u("MultiType");
    u.add(&ByteDataType::dataType());
    u.add(&WordDataType::dataType(), 2);
    u.add(&DWordDataType::dataType(), 4);
    u.add(&FloatDataType::dataType(), 4);
    TEST("union.multi.num", u.getNumComponents() == 4);
    TEST("union.multi.len", u.getLength() == 4);
    TEST("union.multi.maxLen", u.getLength() == 4);
}

void test_union_add_with_length() {
    UnionDataType u("LenUnion");
    u.add(&ByteDataType::dataType(), 8);
    TEST("union.addLen.len", u.getLength() == 8);
    DataTypeComponent* c = u.getComponent(0);
    TEST("union.addLen.compLen", c != nullptr && c->getLength() == 8);
}

void test_union_insert_named() {
    UnionDataType u("InsNamedUnion");
    u.add(&ByteDataType::dataType());
    u.insert(0, &IntegerDataType::dataType(), 4, "ins", "inserted");
    DataTypeComponent* c0 = u.getComponent(0);
    TEST("union.insNamed.c0.notIns", c0 != nullptr && c0->getFieldName() != "ins");
    DataTypeComponent* c1 = u.getComponent(1);
    TEST("union.insNamed.c1.name", c1 != nullptr && c1->getFieldName() == "ins");
    TEST("union.insNamed.c1.comment", c1 != nullptr && c1->getComment() == "inserted");
}

// ---- EnumDataType tests ----

void test_enum_basic() {
    EnumDataType e("MyEnum", 4);
    TEST("enum.name", e.getName() == "MyEnum");
    TEST("enum.length", e.getLength() == 4);
    TEST("enum.count", e.getCount() == 0);
    TEST("enum.mnemonic", e.getMnemonic(nullptr) == e.getName());
    TEST("enum.labelPrefix", e.getDefaultLabelPrefix() == "");
}

void test_enum_add() {
    EnumDataType e("AddEnum", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    e.add("TWO", 2);
    TEST("enum.add.count", e.getCount() == 3);
    TEST("enum.add.values.size", e.getValues().size() == 3);
    TEST("enum.add.names.size", e.getNames().size() == 3);
}

void test_enum_get_value() {
    EnumDataType e("GetVal", 2);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    e.add("MAX", 65535);
    TEST("enum.getVal.ZERO", e.getValue("ZERO") == 0);
    TEST("enum.getVal.ONE", e.getValue("ONE") == 1);
    TEST("enum.getVal.MAX", e.getValue("MAX") == 65535);
}

void test_enum_get_name() {
    EnumDataType e("GetName", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    TEST("enum.getName.0", e.getName(0) == "ZERO");
    TEST("enum.getName.1", e.getName(1) == "ONE");
}

void test_enum_get_names_for_value() {
    EnumDataType e("NameList", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    e.add("ALSO_ONE", 1);
    auto names = e.getNames(1);
    TEST("enum.namesForVal.size", names.size() == 2);
}

void test_enum_contains_name() {
    EnumDataType e("Contains", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    TEST("enum.contains.name.ZERO", e.contains("ZERO"));
    TEST("enum.contains.name.MISSING", e.contains("MISSING") == false);
}

void test_enum_contains_value() {
    EnumDataType e("ContainsVal", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    TEST("enum.contains.val.0", e.contains(0));
    TEST("enum.contains.val.99", e.contains(99) == false);
}

void test_enum_remove() {
    EnumDataType e("RemoveTest", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    e.remove("ZERO");
    TEST("enum.remove.count", e.getCount() == 1);
    TEST("enum.remove.contains", e.contains("ZERO") == false);
    TEST("enum.remove.contains.ONE", e.contains("ONE"));
}

void test_enum_add_with_comment() {
    EnumDataType e("CommentTest", 1);
    e.add("MYVAL", 42, "the answer");
    TEST("enum.addComment.comment", e.getComment("MYVAL") == "the answer");
}

void test_enum_signed() {
    EnumDataType e("SignedTest", 1);
    e.add("NEG", -1);
    e.add("POS", 1);
    TEST("enum.signed.true", e.isSigned());
    EnumDataType e2("UnsignedTest", 1);
    e2.add("ONE", 1);
    e2.add("TWO", 2);
    TEST("enum.signed.false", e2.isSigned() == false);
}

void test_enum_get_min_max() {
    EnumDataType e("MinMax", 1);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    TEST("enum.minPossible", e.getMinPossibleValue() == -128);
    TEST("enum.maxPossible", e.getMaxPossibleValue() == 255);
    TEST("enum.minLength", e.getMinimumPossibleLength() == 1);
}

void test_enum_min_possible_signed() {
    EnumDataType e("MinMaxS", 1);
    e.add("NEG", -1);
    e.add("POS", 1);
    TEST("enum.minPossible.signed", e.getMinPossibleValue() == -128);
    TEST("enum.maxPossible.signed", e.getMaxPossibleValue() == 127);
}

void test_enum_clone() {
    EnumDataType e("CloneEnum", 2);
    e.add("ZERO", 0);
    e.add("ONE", 1);
    StandAloneDataTypeManager mgr("test");
    DataType* cloned = e.clone(&mgr);
    TEST("enum.clone.name", cloned->getName() == "CloneEnum");
    EnumDataType* eCloned = dynamic_cast<EnumDataType*>(cloned);
    TEST("enum.clone.type", eCloned != nullptr);
    TEST("enum.clone.count", eCloned != nullptr && eCloned->getCount() == 2);
    TEST("enum.clone.length", cloned->getLength() == 2);
    delete cloned;
}

void test_enum_copy() {
    EnumDataType e("CopyEnum", 4);
    e.add("VAL", 100);
    StandAloneDataTypeManager mgr("test");
    DataType* copied = e.copy(&mgr);
    TEST("enum.copy.name", copied->getName() == "CopyEnum");
    TEST("enum.copy.length", copied->getLength() == 4);
    delete copied;
}

void test_enum_is_equivalent() {
    EnumDataType e1("SameEnumEq", 1);
    e1.add("ZERO", 0);
    e1.add("ONE", 1);
    EnumDataType e2("SameEnumEq", 1);
    e2.add("ZERO", 0);
    e2.add("ONE", 1);
    TEST("enum.eq.same", e1.isEquivalent(&e2));
    EnumDataType e3("DiffEnumEq", 1);
    e3.add("ZERO", 0);
    TEST("enum.eq.diff", e1.isEquivalent(&e3) == false);
}

void test_enum_aligned_length() {
    EnumDataType e("Align", 1);
    TEST("enum.aligned.1", e.getAlignedLength() == 1);
    EnumDataType e4("Align4", 4);
    TEST("enum.aligned.4", e4.getAlignedLength() == 4);
}

void test_enum_category_path() {
    CategoryPath cat("/test/path");
    EnumDataType e(cat, "CatEnum", 2);
    TEST("enum.catPath.path", e.getCategoryPath().getPath() == "/test/path");
    TEST("enum.catPath.name", e.getName() == "CatEnum");
}

// ---- TypedefDataType tests ----

void test_typedef_basic() {
    TypedefDataType td("MyInt", &IntegerDataType::dataType());
    TEST("typedef.name", td.getName() == "MyInt");
    TEST("typedef.base", td.getDataType() == &IntegerDataType::dataType());
    TEST("typedef.length", td.getLength() == 4);
    TEST("typedef.mnemonic", td.getMnemonic(nullptr) == td.getName());
    TEST("typedef.autoNamed", td.isAutoNamed() == false);
}

void test_typedef_enable_auto_naming() {
    TypedefDataType td("MyInt", &IntegerDataType::dataType());
    td.enableAutoNaming();
    TEST("typedef.autoNamed.enabled", td.isAutoNamed());
}

void test_typedef_get_base_data_type() {
    TypedefDataType td("MyInt", &IntegerDataType::dataType());
    TEST("typedef.baseDataType", td.getBaseDataType() == &IntegerDataType::dataType());
}

void test_typedef_is_equivalent() {
    TypedefDataType td1("SameTypedef", &IntegerDataType::dataType());
    TypedefDataType td2("SameTypedef", &IntegerDataType::dataType());
    TEST("typedef.eq.same", td1.isEquivalent(&td2));
    TypedefDataType td3("DiffTypedef", &ByteDataType::dataType());
    TEST("typedef.eq.diff", td1.isEquivalent(&td3) == false);
}

void test_typedef_clone() {
    TypedefDataType td("CloneTd", &IntegerDataType::dataType());
    StandAloneDataTypeManager mgr("test");
    DataType* cloned = td.clone(&mgr);
    TEST("typedef.clone.name", cloned->getName() == "CloneTd");
    TEST("typedef.clone.length", cloned->getLength() == 4);
    delete cloned;
}

void test_typedef_copy() {
    TypedefDataType td("CopyTd", &IntegerDataType::dataType());
    StandAloneDataTypeManager mgr("test");
    DataType* copied = td.copy(&mgr);
    TEST("typedef.copy.name", copied->getName() == "CopyTd");
    delete copied;
}

void test_typedef_has_lang_dep_length() {
    TypedefDataType td("LenDep", &IntegerDataType::dataType());
    TEST("typedef.langDepLen", td.hasLanguageDependantLength());
}

void test_typedef_is_zero_length() {
    TypedefDataType td("Zero", &ByteDataType::dataType());
    TEST("typedef.isZero", td.isZeroLength() == false);
}

void test_typedef_description() {
    TypedefDataType td("Desc", &IntegerDataType::dataType());
    TEST("typedef.desc", td.getDescription() == IntegerDataType::dataType().getDescription());
}

void test_typedef_category_path() {
    CategoryPath cat("/my/types");
    TypedefDataType td(cat, "CatTd", &ByteDataType::dataType());
    TEST("typedef.catPath.path", td.getCategoryPath().getPath() == "/my/types");
    TEST("typedef.catPath.name", td.getName() == "CatTd");
}

// ---- CompositeDataTypeImpl tests ----

void test_composite_alignment_default() {
    StructureDataType s("AlignDef", 4);
    s.add(&ByteDataType::dataType());
    TEST("composite.alignType.default", s.getAlignmentType() == AlignmentType::DEFAULT);
    TEST("composite.isDefaultAligned", s.isDefaultAligned());
    TEST("composite.isMachineAligned", s.isMachineAligned() == false);
}

void test_composite_set_machine_aligned() {
    StructureDataType s("MachAlign", 4);
    s.setToMachineAligned();
    TEST("composite.machineAligned", s.getAlignmentType() == AlignmentType::MACHINE);
    TEST("composite.isMachineAligned.machine", s.isMachineAligned());
}

void test_composite_explicit_alignment() {
    StructureDataType s("ExpAlign", 8);
    s.setExplicitMinimumAlignment(8);
    TEST("composite.expAlign", s.getAlignmentType() == AlignmentType::EXPLICIT);
    TEST("composite.expAlign.value", s.getExplicitMinimumAlignment() == 8);
}

void test_composite_packing_default() {
    StructureDataType s("PackDef", 0);
    TEST("composite.packType.default", s.getPackingType() == PackingType::DISABLED);
    TEST("composite.isPackingEnabled", s.isPackingEnabled() == false);
    TEST("composite.hasDefaultPacking", s.hasDefaultPacking() == false);
    TEST("composite.hasExplicitPacking", s.hasExplicitPackingValue() == false);
}

void test_composite_set_packing_disabled() {
    StructureDataType s("PackDis", 4);
    s.setPackingEnabled(false);
    TEST("composite.packDisabled", s.getPackingType() == PackingType::DISABLED);
}

void test_composite_explicit_packing() {
    StructureDataType s("ExpPack", 8);
    s.setExplicitPackingValue(4);
    TEST("composite.expPackValue", s.getExplicitPackingValue() == 4);
    TEST("composite.hasExplicitPack", s.hasExplicitPackingValue());
}

void test_composite_pack_method() {
    StructureDataType s("PackMethod", 8);
    s.pack(2);
    TEST("composite.packMethod.value", s.getExplicitPackingValue() == 2);
    TEST("composite.hasExplicitPack.packed", s.hasExplicitPackingValue());
}

void test_composite_align_method() {
    StructureDataType s("AlignMethod", 8);
    s.align(4);
    TEST("composite.alignMethod.value", s.getExplicitMinimumAlignment() == 4);
}

void test_composite_is_not_yet_defined() {
    StructureDataType s("NotYet", 0);
    TEST("composite.notYetDefined.empty", s.isNotYetDefined());
    StructureDataType s2("NotYet2", 4);
    s2.add(&ByteDataType::dataType());
    TEST("composite.notYetDefined.withData", s2.isNotYetDefined() == false);
}

void test_composite_is_part_of() {
    StructureDataType s("PartOf", 0);
    s.add(&ByteDataType::dataType());
    TEST("composite.isPartOf.byte", s.isPartOf(&ByteDataType::dataType()));
    TEST("composite.isPartOf.int", s.isPartOf(&IntegerDataType::dataType()) == false);
    TEST("composite.isPartOf.self", s.isPartOf(&s) == false);
}

void test_composite_get_aligned_length() {
    StructureDataType s("AlignedLen", 10);
    int aligned = s.getAlignedLength();
    TEST("composite.alignedLen", aligned >= 10);
}

void test_composite_is_zero_length() {
    StructureDataType s("ZeroComp", 0);
    TEST("composite.isZero", s.isZeroLength());
    StructureDataType s2("NonZero", 4);
    TEST("composite.isNonZero", s2.isZeroLength() == false);
}

// ---- CompositeInternal tests ----

void test_composite_internal_constants() {
    TEST("ci.DEFAULT_PACKING", CompositeInternal::DEFAULT_PACKING == 0);
    TEST("ci.NO_PACKING", CompositeInternal::NO_PACKING == -1);
    TEST("ci.DEFAULT_ALIGNMENT", CompositeInternal::DEFAULT_ALIGNMENT == 0);
    TEST("ci.MACHINE_ALIGNMENT", CompositeInternal::MACHINE_ALIGNMENT == -1);
}

// ---- CompositeAlignmentHelper tests ----

void test_alignment_helper_packed_alignment() {
    int align = CompositeAlignmentHelper::getPackedAlignment(4, 2);
    TEST("align.helper.packed.4.2", align == 2);
    align = CompositeAlignmentHelper::getPackedAlignment(4, 0);
    TEST("align.helper.packed.4.0", align == 4);
    align = CompositeAlignmentHelper::getPackedAlignment(4, 8);
    TEST("align.helper.packed.4.8", align == 4);
}

} // anonymous namespace

int main() {
    // Structure tests
    test_struct_basic();
    test_struct_add_bytes();
    test_struct_add_named();
    test_struct_add_with_length();
    test_struct_insert();
    test_struct_insert_at_offset();
    test_struct_delete_component();
    test_struct_delete_all();
    test_struct_clear();
    test_struct_replace();
    test_struct_get_components();
    test_struct_is_equivalent();
    test_struct_clone();
    test_struct_copy();
    test_struct_grow();
    test_struct_set_length();
    test_struct_get_defined_components();
    test_struct_get_component_containing();
    test_struct_delete_components_set();
    test_struct_add_bitfield();
    test_struct_insert_bitfield();
    test_struct_find_component();
    test_struct_delete_at_offset();
    test_struct_clear_component();
    test_struct_insert_named();
    test_struct_replace_named();
    test_struct_replace_at_offset();
    test_struct_get_defined_component_at_or_after();
    test_struct_get_data_type_at();
    test_struct_repack();
    test_struct_multiple_adds();
    test_struct_category_path();
    test_struct_insert_at_offset_named();

    // Union tests
    test_union_basic();
    test_union_add();
    test_union_add_named();
    test_union_insert();
    test_union_delete();
    test_union_delete_set();
    test_union_repack();
    test_union_clone();
    test_union_copy();
    test_union_is_equivalent();
    test_union_get_components();
    test_union_find_component();
    test_union_zero_length();
    test_union_multiple_types();
    test_union_add_with_length();
    test_union_insert_named();

    // Enum tests
    test_enum_basic();
    test_enum_add();
    test_enum_get_value();
    test_enum_get_name();
    test_enum_get_names_for_value();
    test_enum_contains_name();
    test_enum_contains_value();
    test_enum_remove();
    test_enum_add_with_comment();
    test_enum_signed();
    test_enum_get_min_max();
    test_enum_min_possible_signed();
    test_enum_clone();
    test_enum_copy();
    test_enum_is_equivalent();
    test_enum_aligned_length();
    test_enum_category_path();

    // Typedef tests
    test_typedef_basic();
    test_typedef_enable_auto_naming();
    test_typedef_get_base_data_type();
    test_typedef_is_equivalent();
    test_typedef_clone();
    test_typedef_copy();
    test_typedef_has_lang_dep_length();
    test_typedef_is_zero_length();
    test_typedef_description();
    test_typedef_category_path();

    // CompositeDataTypeImpl tests
    test_composite_alignment_default();
    test_composite_set_machine_aligned();
    test_composite_explicit_alignment();
    test_composite_packing_default();
    test_composite_set_packing_disabled();
    test_composite_explicit_packing();
    test_composite_pack_method();
    test_composite_align_method();
    test_composite_is_not_yet_defined();
    test_composite_is_part_of();
    test_composite_get_aligned_length();
    test_composite_is_zero_length();

    // CompositeInternal tests
    test_composite_internal_constants();

    // CompositeAlignmentHelper tests
    test_alignment_helper_packed_alignment();

    std::cout << "Batch T: " << passed << "/" << total << " passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
