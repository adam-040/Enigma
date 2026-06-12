/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_r.cpp
/// \brief Tests for Batch R: BitGroup, EnumValuePartitioner, ReadOnlyDataTypeComponent, BuiltInDataTypeManager
#include <ghidra/BitGroup.h>
#include <ghidra/EnumValuePartitioner.h>
#include <ghidra/ReadOnlyDataTypeComponent.h>
#include <ghidra/BuiltInDataTypeManager.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/CategoryPath.h>
#include <iostream>
#include <vector>
#include <set>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// ---- BitGroup tests ----

void test_bitgroup_construct() {
    BitGroup bg(0x1234);
    TEST("BitGroup.mask", bg.getMask() == 0x1234);
    TEST("BitGroup.values.size", bg.getValues().size() == 1);
    TEST("BitGroup.contains", bg.getValues().count(0x1234) == 1);
}

void test_bitgroup_intersects() {
    BitGroup a(0x0010);
    BitGroup b(0x0100);
    BitGroup c(0x0010);
    TEST("BitGroup.intersects.false", !a.intersects(b));
    TEST("BitGroup.intersects.true", a.intersects(c));
}

void test_bitgroup_merge() {
    BitGroup a(0x0010);
    BitGroup b(0x0100);
    a.merge(b);
    TEST("BitGroup.merge.mask", a.getMask() == 0x0110);
    TEST("BitGroup.merge.values", a.getValues().size() == 2);
    TEST("BitGroup.merge.contains.a", a.getValues().count(0x0010) == 1);
    TEST("BitGroup.merge.contains.b", a.getValues().count(0x0100) == 1);
}

void test_bitgroup_toString() {
    BitGroup bg(0xFF);
    std::string s = bg.toString();
    TEST("BitGroup.toString.contains", s.find("BitGroup") != std::string::npos);
}

// ---- EnumValuePartitioner tests ----

void test_partitioner_empty() {
    std::vector<int64_t> values;
    auto result = EnumValuePartitioner::partition(values, 1);
    TEST("Partitioner.empty", result.size() == 1);
    TEST("Partitioner.empty.mask", result[0].getMask() == 0xFF);
}

void test_partitioner_single() {
    std::vector<int64_t> values = {0x01};
    auto result = EnumValuePartitioner::partition(values, 1);
    TEST("Partitioner.single", result.size() == 2);
}

void test_partitioner_two_nonintersecting() {
    std::vector<int64_t> values = {0x01, 0x10};
    auto result = EnumValuePartitioner::partition(values, 1);
    TEST("Partitioner.nonintersecting.1", result.size() >= 2);
    bool foundA = false, foundB = false;
    for (auto& bg : result) {
        if (bg.getMask() == 0x01) foundA = true;
        if (bg.getMask() == 0x10) foundB = true;
    }
    TEST("Partitioner.nonintersecting.maskA", foundA);
    TEST("Partitioner.nonintersecting.maskB", foundB);
}

void test_partitioner_intersecting() {
    std::vector<int64_t> values = {0x01, 0x03};
    auto result = EnumValuePartitioner::partition(values, 1);
    bool merged = false;
    for (auto& bg : result) {
        if (bg.getMask() == 0x03 && bg.getValues().size() == 2) {
            merged = true;
        }
    }
    TEST("Partitioner.intersecting.merged", merged);
}

// ---- ReadOnlyDataTypeComponent tests ----

void test_readonly_construct() {
    IntegerDataType intDt;
    ReadOnlyDataTypeComponent comp(&intDt, nullptr, 4, 0, 0, "field0", "a comment");
    TEST("ReadOnly.getDataType", comp.getDataType() == &intDt);
    TEST("ReadOnly.getParent", comp.getParent() == nullptr);
    TEST("ReadOnly.getOrdinal", comp.getOrdinal() == 0);
    TEST("ReadOnly.getOffset", comp.getOffset() == 0);
    TEST("ReadOnly.getLength", comp.getLength() == 4);
    TEST("ReadOnly.getEndOffset", comp.getEndOffset() == 3);
    TEST("ReadOnly.getComment", comp.getComment() == "a comment");
    TEST("ReadOnly.getFieldName", comp.getFieldName() == "field0");
    TEST("ReadOnly.isUndefined", !comp.isUndefined());
    TEST("ReadOnly.isBitFieldComponent", !comp.isBitFieldComponent());
    TEST("ReadOnly.isZeroBitFieldComponent", !comp.isZeroBitFieldComponent());
}

void test_readonly_length_zero() {
    IntegerDataType intDt;
    ReadOnlyDataTypeComponent comp(&intDt, nullptr, 0, 0, 0);
    TEST("ReadOnly.zeroLength", comp.getLength() == 1);
}

void test_readonly_default_fieldname() {
    IntegerDataType intDt;
    ReadOnlyDataTypeComponent comp(&intDt, nullptr, 4, 5, 10);
    TEST("ReadOnly.defaultFieldName", comp.getFieldName() == "field5");
}

void test_readonly_setters_noop() {
    IntegerDataType intDt;
    ReadOnlyDataTypeComponent comp(&intDt, nullptr, 4, 0, 0);
    auto* result = comp.setComment("new comment");
    TEST("ReadOnly.setComment.returns_this", result == &comp);
    TEST("ReadOnly.setComment.noop", comp.getComment().empty());
    result = comp.setFieldName("new name");
    TEST("ReadOnly.setFieldName.returns_this", result == &comp);
    TEST("ReadOnly.setFieldName.noop", comp.getFieldName() != "new name");
}

void test_readonly_equivalent() {
    IntegerDataType intDt;
    ReadOnlyDataTypeComponent a(&intDt, nullptr, 4, 0, 0, "f0", "");
    ReadOnlyDataTypeComponent b(&intDt, nullptr, 4, 0, 0, "f0", "");
    TEST("ReadOnly.isEquivalent.same", a.isEquivalent(&b));
}

void test_readonly_not_equivalent() {
    IntegerDataType intDt;
    ByteDataType byteDt;
    ReadOnlyDataTypeComponent a(&intDt, nullptr, 4, 0, 0);
    ReadOnlyDataTypeComponent b(&byteDt, nullptr, 1, 0, 0);
    TEST("ReadOnly.isEquivalent.diff", !a.isEquivalent(&b));
}

void test_readonly_default_settings() {
    IntegerDataType intDt;
    ReadOnlyDataTypeComponent comp(&intDt, nullptr, 4, 0, 0);
    auto* settings = comp.getDefaultSettings();
    TEST("ReadOnly.getDefaultSettings.notNull", settings != nullptr);
    // Calling again returns same pointer
    auto* settings2 = comp.getDefaultSettings();
    TEST("ReadOnly.getDefaultSettings.cached", settings2 == settings);
}

// ---- BuiltInDataTypeManager tests ----

void test_builtin_singleton() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    TEST("BuiltIn.name", mgr.getName() == std::string("BuiltInTypes"));
    TEST("BuiltIn.type", mgr.getType() == ArchiveType::BUILT_IN);
    TEST("BuiltIn.rootCategory", mgr.getRootCategory() != nullptr);
}

void test_builtin_has_integer() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    auto* dt = mgr.getDataType(CategoryPath::ROOT(), "int");
    TEST("BuiltIn.has.int", dt != nullptr);
    TEST("BuiltIn.int.type", dynamic_cast<IntegerDataType*>(dt) != nullptr);
}

void test_builtin_has_byte() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    auto* dt = mgr.getDataType(CategoryPath::ROOT(), "byte");
    TEST("BuiltIn.has.byte", dt != nullptr);
    TEST("BuiltIn.byte.type", dynamic_cast<ByteDataType*>(dt) != nullptr);
}

void test_builtin_has_void() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    auto* dt = mgr.getDataType(CategoryPath::ROOT(), "void");
    TEST("BuiltIn.has.void", dt != nullptr);
}

void test_builtin_cannot_modify() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    bool threw = false;
    try {
        mgr.startTransaction("test");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    TEST("BuiltIn.startTransaction.throws", threw);
}

void test_builtin_cannot_remove() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    auto* intDt = mgr.getDataType(CategoryPath::ROOT(), "int");
    bool threw = false;
    try {
        mgr.remove(intDt);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    TEST("BuiltIn.remove.throws", threw);
}

void test_builtin_cannot_rename() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    bool threw = false;
    try {
        mgr.setName("NewName");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    TEST("BuiltIn.setName.throws", threw);
}

void test_builtin_cannot_add() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    IntegerDataType intDt;
    bool threw = false;
    try {
        mgr.addDataType(&intDt, nullptr);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    TEST("BuiltIn.addDataType.throws", threw);
}

void test_builtin_no_undo() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    TEST("BuiltIn.canUndo", !mgr.canUndo());
    TEST("BuiltIn.canRedo", !mgr.canRedo());
}

void test_builtin_resolve() {
    auto& mgr = BuiltInDataTypeManager::getDataTypeManager();
    IntegerDataType intDt;
    auto* resolved = mgr.resolve(&intDt, nullptr);
    TEST("BuiltIn.resolve", resolved != nullptr);
    TEST("BuiltIn.resolve.isInteger", dynamic_cast<IntegerDataType*>(resolved) != nullptr);
}

} // anonymous namespace

int main() {
    test_bitgroup_construct();
    test_bitgroup_intersects();
    test_bitgroup_merge();
    test_bitgroup_toString();

    test_partitioner_empty();
    test_partitioner_single();
    test_partitioner_two_nonintersecting();
    test_partitioner_intersecting();

    test_readonly_construct();
    test_readonly_length_zero();
    test_readonly_default_fieldname();
    test_readonly_setters_noop();
    test_readonly_equivalent();
    test_readonly_not_equivalent();
    test_readonly_default_settings();

    test_builtin_singleton();
    test_builtin_has_integer();
    test_builtin_has_byte();
    test_builtin_has_void();
    test_builtin_cannot_modify();
    test_builtin_cannot_remove();
    test_builtin_cannot_rename();
    test_builtin_cannot_add();
    test_builtin_no_undo();
    test_builtin_resolve();

    std::cout << "Batch R: " << passed << "/" << total << " passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
