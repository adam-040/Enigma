/**
 * Enigma Engine - DataTypeMerger Test
 * Validates Task 4.1: DataTypeMerger merges types between DataTypeManagers
 * with conflict resolution. Covers:
 *   - MERGE: primitive types copied correctly
 *   - MERGE: structure types with fields
 *   - CONFLICT: existing equivalent type reused
 *   - MERGE: pointer types with resolved targets
 *   - MERGE: array types with resolved elements
 *   - ID mapping correctness
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

#include "ghidra/DataTypeMerger.h"
#include "ghidra/DataTypeConflictHandler.h"
#include "ghidra/StandAloneDataTypeManager.h"
#include "ghidra/StructureDataType.h"
#include "ghidra/PointerDataType.h"
#include "ghidra/ArrayDataType.h"
#include "ghidra/IntegerDataType.h"
#include "ghidra/CharDataType.h"
#include "ghidra/CategoryPath.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

static StandAloneDataTypeManager* createDTM(const std::string& name) {
    return new StandAloneDataTypeManager(name);
}

int main() {
    StandAloneDataTypeManager* srcDTM = createDTM("source");
    StandAloneDataTypeManager* tgtDTM = createDTM("target");

    IntegerDataType* intType = new IntegerDataType();
    srcDTM->addDataType(intType, nullptr);

    CharDataType* charType = new CharDataType();
    srcDTM->addDataType(charType, nullptr);

    StructureDataType* srcStruct = new StructureDataType("MyStruct", 16, srcDTM);
    srcStruct->insertAtOffset(0, intType, 4, "field0", "");
    srcStruct->insertAtOffset(4, charType, 1, "field1", "");
    srcDTM->addDataType(srcStruct, nullptr);

    PointerDataType* ptrToInt = new PointerDataType(intType, srcDTM);
    srcDTM->addDataType(ptrToInt, nullptr);

    ArrayDataType* arrOfChar = new ArrayDataType(charType, 32, 1, srcDTM);
    srcDTM->addDataType(arrOfChar, nullptr);

    int srcCount = srcDTM->getDataTypes().size();
    TEST("source DTM has types", srcCount >= 5);

    // === Test 1: Merge into empty target ===
    {
        DataTypeMerger merger(tgtDTM, srcDTM, nullptr);
        bool ok = merger.merge();
        TEST("merge into empty target succeeds", ok);
        TEST("merge count > 0", merger.getMergeCount() > 0);

        int tgtCount = tgtDTM->getDataTypes().size();
        TEST("target has merged types", tgtCount >= 5);
    }

    // === Test 2: Merge equivalent types (should reuse existing) ===
    {
        int prevCount = tgtDTM->getDataTypes().size();
        DataTypeConflictHandler& handler = DataTypeConflictHandler::KEEP_HANDLER();
        DataTypeMerger merger(tgtDTM, srcDTM, &handler);
        bool ok = merger.merge();
        TEST("re-merge succeeds", ok);
        TEST("no skips on re-merge", merger.getSkipCount() == 0);

        int newCount = tgtDTM->getDataTypes().size();
        TEST("no duplicate types added", newCount == prevCount);
    }

    // === Test 3: Verify structure was merged ===
    {
        DataType* mergedStruct = tgtDTM->getDataType(CategoryPath("/"), "MyStruct");
        TEST("MyStruct exists in target", mergedStruct != nullptr);

        StructureDataType* asStruct = dynamic_cast<StructureDataType*>(mergedStruct);
        TEST("MyStruct is StructureDataType", asStruct != nullptr);
        if (asStruct) {
            TEST("MyStruct has fields", asStruct->getNumComponents() >= 2);
        }
    }

    // === Test 4: Verify pointer was merged ===
    {
        DataType* mergedPtr = tgtDTM->resolve(ptrToInt, nullptr);
        TEST("pointer type resolved", mergedPtr != nullptr);

        PointerDataType* asPtr = dynamic_cast<PointerDataType*>(mergedPtr);
        TEST("pointer is PointerDataType", asPtr != nullptr);
        if (asPtr) {
            DataType* base = asPtr->getDataType();
            TEST("pointer target is int", base != nullptr && base->getName() == "int");
        }
    }

    // === Test 5: Verify array was merged ===
    {
        DataType* mergedArr = tgtDTM->resolve(arrOfChar, nullptr);
        TEST("array type resolved", mergedArr != nullptr);

        ArrayDataType* asArr = dynamic_cast<ArrayDataType*>(mergedArr);
        TEST("array is ArrayDataType", asArr != nullptr);
        if (asArr) {
            TEST("array element count == 32", asArr->getNumElements() == 32);
        }
    }

    // === Test 6: ID mapping ===
    {
        DataTypeMerger merger(tgtDTM, srcDTM, nullptr);
        merger.merge();
        const auto& idMap = merger.getIdMap();
        TEST("ID map is not empty", !idMap.empty());
    }

    std::cout << "DataTypeMerger Tests: " << passed << "/" << total << " passed.\n" << std::flush;

    delete srcDTM;
    delete tgtDTM;

    return (passed == total) ? 0 : 1;
}
