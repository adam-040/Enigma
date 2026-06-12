/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_p.cpp
/// \brief Tests for Batch P: BadDataType, MissingBuiltInDataType, MetaDataType,
///        DataTypeInstance, PointerTypedef, PointerTypedefBuilder, AbstractPointerTypedefBuiltIn
#include <ghidra/BadDataType.h>
#include <ghidra/MissingBuiltInDataType.h>
#include <ghidra/MetaDataType.h>
#include <ghidra/DataTypeInstance.h>
#include <ghidra/PointerTypedef.h>
#include <ghidra/PointerTypedefBuilder.h>
#include <ghidra/AbstractPointerTypedefBuiltIn.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/PointerType.h>
#include <iostream>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

void test_bad_data_type() {
    BadDataType& bd = BadDataType::dataType;
    TEST("BadDataType.singleton", &BadDataType::dataType == &bd);
    TEST("BadDataType.length", bd.getLength() == -1);
    TEST("BadDataType.description", bd.getDescription() == "** Bad Data Type **");
    TEST("BadDataType.mnemonic", bd.getMnemonic(nullptr) == bd.getName());
    TEST("BadDataType.clone.self", bd.clone(nullptr) == &bd);
    TEST("BadDataType.canSpecify", bd.canSpecifyLength());
    TEST("BadDataType.replacement", bd.getReplacementBaseType() == nullptr);
    TEST("BadDataType.dynamicLen", bd.getLength(nullptr, 100) == -1);
}

void test_missing_built_in() {
    CategoryPath root = CategoryPath::ROOT();
    MissingBuiltInDataType mb(root, "MyType", "com.example.Missing", nullptr);

    TEST("MissingBuiltIn.name", mb.getMissingBuiltInName() == "MyType");
    TEST("MissingBuiltIn.classpath", mb.getMissingBuiltInClassPath() == "com.example.Missing");
    TEST("MissingBuiltIn.length", mb.getLength() == -1);
    TEST("MissingBuiltIn.mnemonic", mb.getMnemonic(nullptr) == mb.getName());
    TEST("MissingBuiltIn.canSpecify", mb.canSpecifyLength());
    TEST("MissingBuiltIn.dynamicLen", mb.getLength(nullptr, 50) == -1);

    std::string desc = mb.getDescription();
    TEST("MissingBuiltIn.description", desc.find("Missing Built-In") != std::string::npos);
    TEST("MissingBuiltIn.desc.classpath", desc.find("com.example.Missing") != std::string::npos);

    TEST("MissingBuiltIn.representation", mb.getRepresentation(nullptr, nullptr, 0) == "com.example.Missing");

    // clone with same dtm returns self
    TEST("MissingBuiltIn.clone.self", mb.clone(nullptr) == &mb);

    // copy returns self (dtm same = nullptr)
    DataType* copied = mb.copy(nullptr);
    TEST("MissingBuiltIn.copy", copied == &mb);

    MissingBuiltInDataType mb2(root, "MyType", "com.example.Missing", nullptr);
    TEST("MissingBuiltIn.isEquivalent", mb.isEquivalent(&mb2));

    MissingBuiltInDataType mb3(root, "Other", "com.example.Other", nullptr);
    TEST("MissingBuiltIn.notEquiv", !mb.isEquivalent(&mb3));

    TEST("MissingBuiltIn.isEquiv.null", !mb.isEquivalent(nullptr));

    TEST("MissingBuiltIn.changeTime", mb.getLastChangeTime() == 0);
    TEST("MissingBuiltIn.replacement", mb.getReplacementBaseType() == nullptr);
}

void test_meta_data_type_enum() {
    TEST("MetaDataType.VOID.ord", static_cast<int>(MetaDataType::VOID) == 0);
    TEST("MetaDataType.UNKNOWN.ord", static_cast<int>(MetaDataType::UNKNOWN) == 1);
    TEST("MetaDataType.INT.ord", static_cast<int>(MetaDataType::INT) == 2);
    TEST("MetaDataType.UINT.ord", static_cast<int>(MetaDataType::UINT) == 3);
    TEST("MetaDataType.BOOL.ord", static_cast<int>(MetaDataType::BOOL) == 4);
    TEST("MetaDataType.CODE.ord", static_cast<int>(MetaDataType::CODE) == 5);
    TEST("MetaDataType.FLOAT.ord", static_cast<int>(MetaDataType::FLOAT) == 6);
    TEST("MetaDataType.PTR.ord", static_cast<int>(MetaDataType::PTR) == 7);
    TEST("MetaDataType.ARRAY.ord", static_cast<int>(MetaDataType::ARRAY) == 8);
    TEST("MetaDataType.STRUCT.ord", static_cast<int>(MetaDataType::STRUCT) == 9);
}

void test_meta_data_type_get_meta() {
    IntegerDataType intDt;
    TEST("MetaDataType.getMeta.int", getMeta(&intDt) == MetaDataType::INT);
    TEST("MetaDataType.getMeta.bad", getMeta(&BadDataType::dataType) == MetaDataType::STRUCT);

    PointerDataType ptrDt(nullptr, 8, nullptr);
    TEST("MetaDataType.getMeta.ptr", getMeta(&ptrDt) == MetaDataType::PTR);
}

void test_data_type_instance() {
    TEST("DataTypeInstance.null", DataTypeInstance::getDataTypeInstance(nullptr, 0, false) == nullptr);

    IntegerDataType intDt;
    DataTypeInstance* dti = DataTypeInstance::getDataTypeInstance(&intDt, -1, false);
    TEST("DataTypeInstance.int.exists", dti != nullptr);
    if (dti) {
        TEST("DataTypeInstance.int.length", dti->getLength() == intDt.getLength());
        TEST("DataTypeInstance.int.type", dti->getDataType() == &intDt);
        delete dti;
    }

    DataTypeInstance* dti2 = DataTypeInstance::getDataTypeInstance(&intDt, 8, false);
    TEST("DataTypeInstance.explicitLen", dti2 != nullptr);
    if (dti2) {
        TEST("DataTypeInstance.explicitLen.value", dti2->getLength() == intDt.getLength());
        delete dti2;
    }

    DataTypeInstance* dti3 = DataTypeInstance::getDataTypeInstance(&BadDataType::dataType, 4, false);
    TEST("DataTypeInstance.dynamic", dti3 != nullptr);
    if (dti3) {
        TEST("DataTypeInstance.dynamic.len", dti3->getLength() == 4);
        delete dti3;
    }

    DataTypeInstance* dti4 = DataTypeInstance::getDataTypeInstance(&BadDataType::dataType, 0, false);
    TEST("DataTypeInstance.dynamic.noLen", dti4 == nullptr);

    DataTypeInstance* dti5 = DataTypeInstance::getDataTypeInstance(&intDt, -1, false);
    if (dti5) {
        TEST("DataTypeInstance.toString", dti5->toString() == intDt.toString());
        delete dti5;
    }
}

void test_pointer_typedef() {
    IntegerDataType intDt;
    PointerTypedef pt("MyPtr", &intDt, -1, nullptr);
    TEST("PointerTypedef.name", pt.getName() == "MyPtr");
    TEST("PointerTypedef.description", pt.getDescription() == "Pointer-Typedef");

    DataType* inner = pt.getDataType();
    TEST("PointerTypedef.innerNotNull", inner != nullptr);
    TEST("PointerTypedef.length", pt.getLength() > 0);
    TEST("PointerTypedef.notAutoNamed", !pt.isAutoNamed());

    pt.enableAutoNaming();
    TEST("PointerTypedef.isAutoNamed", pt.isAutoNamed());
}

void test_pointer_typedef_builder() {
    IntegerDataType intDt;
    PointerTypedefBuilder builder(&intDt, -1, nullptr);

    TypeDef* td = builder.build();
    TEST("PtrTypedefBuilder.build", td != nullptr);

    PointerTypedefBuilder builder2(&intDt, -1, nullptr);
    TypeDef* td2 = builder2.name("int_ptr").type(PointerType::DEFAULT).bitShift(2).bitMask(0xFFFF).build();
    TEST("PtrTypedefBuilder.withSettings", td2 != nullptr);
    TEST("PtrTypedefBuilder.name", !td2->isAutoNamed());
}

void test_abstract_pointer_typedef() {
    IntegerDataType intDt;
    AbstractPointerTypedefBuiltIn apt("AbsPtr", &intDt, 8, nullptr);
    TEST("AbsPtrTypedef.name", apt.getName() == "AbsPtr");
    TEST("AbsPtrTypedef.isAutoNamed", !apt.isAutoNamed());
    TEST("AbsPtrTypedef.length", apt.getLength() > 0);
    TEST("AbsPtrTypedef.dataType", apt.getDataType() != nullptr);
    TEST("AbsPtrTypedef.baseType", apt.getBaseDataType() != nullptr);

    apt.enableAutoNaming();
    TEST("AbsPtrTypedef.isAutoNamed2", apt.isAutoNamed());
}

} // anonymous namespace

int main() {
    test_bad_data_type();
    test_missing_built_in();
    test_meta_data_type_enum();
    test_meta_data_type_get_meta();
    test_data_type_instance();
    test_pointer_typedef();
    test_pointer_typedef_builder();
    test_abstract_pointer_typedef();

    std::cout << "\n[Batch P] " << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
