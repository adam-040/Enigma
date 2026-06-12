/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_q.cpp
/// \brief Tests for Batch Q: StandAloneDataTypeManager
#include <ghidra/StandAloneDataTypeManager.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/DataTypeConflictHandler.h>
#include <ghidra/CategoryPath.h>
#include <iostream>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

void test_construct() {
    StandAloneDataTypeManager dtm("TestDTM");
    TEST("SADTM.name", dtm.getName() == "TestDTM");
    TEST("SADTM.type", dtm.getType() == ArchiveType::TEMPORARY);
    TEST("SADTM.rootCategory", dtm.getRootCategory() != nullptr);
    TEST("SADTM.rootCategory.isRoot", dtm.getRootCategory()->isRoot());
    TEST("SADTM.categoryCount", dtm.getCategoryCount() >= 1);
    TEST("SADTM.dataTypeCount", dtm.getDataTypeCount(false) == 0);
    TEST("SADTM.getID.null", dtm.getID(nullptr) == -1);
    TEST("SADTM.contains.empty", !dtm.contains(nullptr));
    TEST("SADTM.isUpdatable", dtm.isUpdatable());
}

void test_set_name() {
    StandAloneDataTypeManager dtm("A");
    dtm.setName("B");
    TEST("SADTM.setName", dtm.getName() == "B");
}

void test_add_and_get() {
    StandAloneDataTypeManager dtm("Test");
    auto* td = new TypedefDataType(CategoryPath("/MyTypes"), "MyInt",
                                   new IntegerDataType(), &dtm);

    DataType* added = dtm.addDataType(td, nullptr);
    TEST("SADTM.add.returnsSame", added == td);
    TEST("SADTM.add.contains", dtm.contains(td));
    TEST("SADTM.add.count", dtm.getDataTypeCount(false) == 1);

    DataType* found = dtm.getDataType(CategoryPath("/MyTypes"), "MyInt");
    TEST("SADTM.get.byPath", found == td);

    long id = dtm.getID(td);
    TEST("SADTM.get.id.valid", id >= 1);
    DataType* foundById = dtm.getDataType(id);
    TEST("SADTM.get.byId", foundById == td);

    DataType* foundByStr = dtm.getDataType("/MyTypes/MyInt");
    TEST("SADTM.get.byString", foundByStr == td);
}

void test_add_resolve_existing() {
    StandAloneDataTypeManager dtm("Test");
    auto* td1 = new TypedefDataType(CategoryPath::ROOT(), "ResolveType",
                                    new IntegerDataType(), &dtm);
    dtm.addDataType(td1, nullptr);

    DataType* resolved = dtm.resolve(td1, nullptr);
    TEST("SADTM.resolve.same", resolved == td1);

    auto* td2 = new TypedefDataType(CategoryPath::ROOT(), "ResolveType",
                                    new IntegerDataType(), &dtm);
    DataType* resolved2 = dtm.resolve(td2, &DataTypeConflictHandler::DEFAULT_HANDLER());
    TEST("SADTM.resolve.useExisting", resolved2 != nullptr);
}

void test_find_data_types() {
    StandAloneDataTypeManager dtm("Test");
    auto* td1 = new TypedefDataType(CategoryPath::ROOT(), "AlphaType",
                                    new IntegerDataType(), &dtm);
    auto* td2 = new TypedefDataType(CategoryPath::ROOT(), "BetaType",
                                    new ByteDataType(), &dtm);

    dtm.addDataType(td1, nullptr);
    dtm.addDataType(td2, nullptr);

    std::vector<DataType*> results;
    dtm.findDataTypes("AlphaType", results);
    TEST("SADTM.find.byName", results.size() >= 1);
    bool found = false;
    for (auto* dt : results) if (dt == td1) found = true;
    TEST("SADTM.find.byName.match", found);

    results.clear();
    dtm.findDataTypes("alphatype", results, false);
    TEST("SADTM.find.caseInsensitive", results.size() >= 1);
}

void test_remove() {
    StandAloneDataTypeManager dtm("Test");
    auto* td = new TypedefDataType(CategoryPath::ROOT(), "RemoveMe",
                                   new IntegerDataType(), &dtm);

    dtm.addDataType(td, nullptr);
    TEST("SADTM.remove.preCount", dtm.getDataTypeCount(false) == 1);

    bool removed = dtm.remove(td);
    TEST("SADTM.remove.success", removed);
    TEST("SADTM.remove.postContains", !dtm.contains(td));
    TEST("SADTM.remove.postCount", dtm.getDataTypeCount(false) == 0);
}

void test_get_pointer() {
    StandAloneDataTypeManager dtm("Test");
    auto* intDt = new IntegerDataType();
    dtm.addDataType(intDt, nullptr);

    Pointer* ptr = dtm.getPointer(intDt);
    TEST("SADTM.getPointer.null", ptr == nullptr);

    auto* manualPtr = new PointerDataType(intDt, 8, &dtm);
    dtm.addDataType(manualPtr, nullptr);

    Pointer* foundPtr = dtm.getPointer(intDt);
    TEST("SADTM.getPointer.found", foundPtr == manualPtr);
}

void test_create_category() {
    StandAloneDataTypeManager dtm("Test");

    CategoryPath catPath("/A/B/C");
    Category* cat = dtm.createCategory(catPath);
    TEST("SADTM.createCategory.nonNull", cat != nullptr);
    TEST("SADTM.createCategory.path",
         cat->getCategoryPath().getPath().find("A/B/C") != std::string::npos);

    Category* same = dtm.createCategory(catPath);
    TEST("SADTM.createCategory.idempotent", same == cat);

    Category* found = dtm.getCategory(catPath);
    TEST("SADTM.getCategory.byPath", found == cat);
}

void test_transaction() {
    StandAloneDataTypeManager dtm("Test");
    int txId = dtm.startTransaction("test tx");
    TEST("SADTM.tx.start", txId >= 0);

    bool committed = dtm.endTransaction(txId, true);
    TEST("SADTM.tx.end.success", committed);

    int txId2 = dtm.startTransaction("rollback");
    dtm.endTransaction(txId2, false);
}

void test_close() {
    auto* dtm = new StandAloneDataTypeManager("Temp");
    auto* td = new TypedefDataType(CategoryPath::ROOT(), "TempType",
                                   new IntegerDataType(), dtm);
    dtm->addDataType(td, nullptr);
    TEST("SADTM.close.preCount", dtm->getDataTypeCount(false) == 1);

    dtm->close();
    TEST("SADTM.close.afterCount", dtm->getDataTypeCount(false) == 0);

    delete dtm;
}

void test_replace_data_type() {
    StandAloneDataTypeManager dtm("Test");
    auto* oldDt = new TypedefDataType(CategoryPath::ROOT(), "OldName",
                                      new IntegerDataType(), &dtm);
    dtm.addDataType(oldDt, nullptr);
    TEST("SADTM.replace.hasOld", dtm.contains(oldDt));

    auto* newDt = new TypedefDataType(CategoryPath::ROOT(), "NewName",
                                      new IntegerDataType(), &dtm);
    DataType* replaced = dtm.replaceDataType(oldDt, newDt, true);
    TEST("SADTM.replace.notNull", replaced != nullptr);
    TEST("SADTM.replace.containsNew", dtm.contains(newDt));
}

} // anonymous namespace

int main() {
    test_construct();
    test_set_name();
    test_add_and_get();
    test_add_resolve_existing();
    test_find_data_types();
    test_remove();
    test_get_pointer();
    test_create_category();
    test_transaction();
    test_close();
    test_replace_data_type();

    std::cout << "\n[Batch Q] " << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
