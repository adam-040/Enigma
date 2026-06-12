#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/TypeDef.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/AddressSet.h>

#include <iostream>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

int main() {
    // ================================================================
    // TEST 1: Pointer target type — verify actual runtime behavior
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("ptr_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* dwordDt = new DWordDataType(dtmImpl);
        dtmImpl->addDataType(dwordDt);
        long dwordId = dtmImpl->getDataTypeId(dwordDt);

        // Create DWORD*
        auto* dwordPtr = new PointerDataType(dwordDt, 8, dtmImpl);
        dtmImpl->addDataType(dwordPtr);
        long ptrId = dtmImpl->getDataTypeId(dwordPtr);

        // Verify before round-trip
        auto* origTarget = dwordPtr->getDataType();
        long origTargetId = dtmImpl->getDataTypeId(origTarget);
        TEST("ptr.pre_target_is_dword", origTarget == dwordDt);
        TEST("ptr.pre_target_id", origTargetId == dwordId);

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restDtmImpl = dynamic_cast<DataTypeManagerImpl*>(restDtm);

        // Find the restored pointer type
        auto* restPtr = restDtm ? restDtm->getDataType(CategoryPath::ROOT(), dwordPtr->getName()) : nullptr;
        TEST("ptr.restored_exists", restPtr != nullptr);

        if (restPtr) {
            auto* ptrCast = dynamic_cast<Pointer*>(restPtr);
            TEST("ptr.is_pointer", ptrCast != nullptr);

            if (ptrCast) {
                auto* restTarget = ptrCast->getDataType();
                TEST("ptr.has_target", restTarget != nullptr);
                if (restTarget) {
                    std::cout << "  ORIGINAL target: " << origTarget->getName() << "\n";
                    std::cout << "  RESTORED target: " << restTarget->getName() << "\n";
                    bool targetIsDword = restTarget->getName() == "dword";
                    TEST("ptr.target_is_dword", targetIsDword);
                    TEST("ptr.target_same_object", restTarget == restDtmImpl->getDataType(CategoryPath::ROOT(), "dword"));
                }
            }
        }
    }

    // ================================================================
    // TEST 2: Array element type — verify actual runtime behavior
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("arr_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* dwordDt = new DWordDataType(dtmImpl);
        dtmImpl->addDataType(dwordDt);

        auto* arr256 = new ArrayDataType(dwordDt, 256, -1, dtmImpl);
        dtmImpl->addDataType(arr256);
        long arrId = dtmImpl->getDataTypeId(arr256);

        // Verify pre-round-trip
        auto* origElem = arr256->getDataType();
        int origCount = arr256->getNumElements();
        TEST("arr.pre_elem_is_dword", origElem == dwordDt);
        TEST("arr.pre_count_256", origCount == 256);

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restDt = restDtm ? restDtm->getDataType(CategoryPath::ROOT(), arr256->getName()) : nullptr;
        TEST("arr.restored_exists", restDt != nullptr);

        if (restDt) {
            auto* arrCast = dynamic_cast<Array*>(restDt);
            TEST("arr.is_array", arrCast != nullptr);

            std::cout << "  ORIGINAL type: ArrayDataType with element=" << origElem->getName()
                      << " count=" << origCount << "\n";
            std::cout << "  RESTORED name: " << restDt->getName() << "\n";

            if (arrCast) {
                auto* restElem = arrCast->getDataType();
                int restCount = arrCast->getNumElements();
                std::cout << "  RESTORED element: " << (restElem ? restElem->getName() : "null")
                          << " count=" << restCount << "\n";
                TEST("arr.elem_is_dword", restElem && restElem->getName() == "dword");
                TEST("arr.count_256", restCount == 256);
            }
        }
    }

    // ================================================================
    // TEST 3: Typedef base type — verify actual runtime behavior
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("td_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* dwordDt = new DWordDataType(dtmImpl);
        dtmImpl->addDataType(dwordDt);

        auto* handleDt = new TypedefDataType(CategoryPath::ROOT(), "HANDLE", dwordDt, dtmImpl);
        dtmImpl->addDataType(handleDt);
        long handleId = dtmImpl->getDataTypeId(handleDt);

        // Verify pre-round-trip
        auto* origBase = handleDt->getBaseDataType();
        TEST("td.pre_base_is_dword", origBase == dwordDt);

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restDt = restDtm ? restDtm->getDataType(CategoryPath::ROOT(), "HANDLE") : nullptr;
        TEST("td.restored_exists", restDt != nullptr);

        if (restDt) {
            auto* tdCast = dynamic_cast<TypeDef*>(restDt);
            TEST("td.is_typedef", tdCast != nullptr);

            std::cout << "  ORIGINAL type: TypedefDataType base=" << origBase->getName() << "\n";
            std::cout << "  RESTORED name: " << restDt->getName() << "\n";

            if (tdCast) {
                auto* restBase = tdCast->getBaseDataType();
                std::cout << "  RESTORED base: " << (restBase ? restBase->getName() : "null") << "\n";
                TEST("td.base_is_dword", restBase && restBase->getName() == "dword");
            }
        }
    }

    // ================================================================
    // TEST 4: Function return type by name after type restoration
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("func_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* dwordDt = new DWordDataType(dtmImpl);
        dtmImpl->addDataType(dwordDt);

        Address entry(nullptr, 0x1000);
        AddressSet body(entry, Address(nullptr, 0x10FF));
        auto* func = prog.getFunctionManager()->createFunction("TestFunc", entry, body, SourceType::USER_DEFINED);
        func->setReturnType(dwordDt, SignatureSource::KNOWN_LIBRARY);

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restFunc = restored->getFunctionManager()->getFunctionAt(entry);
        TEST("fr.func_restored", restFunc != nullptr);
        if (restFunc) {
            auto* ret = restFunc->getReturnType();
            std::cout << "  ORIGINAL return type: " << dwordDt->getName() << "\n";
            std::cout << "  RESTORED return type: " << (ret ? ret->getName() : "null") << "\n";
            TEST("fr.ret_is_dword", ret && ret->getName() == "dword");
        }
    }

    // ================================================================
    // TEST 5: Struct field type (pointer to another type)
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("struct_ptr_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* dwordDt = new DWordDataType(dtmImpl); dtmImpl->addDataType(dwordDt);
        auto* dwordPtr = new PointerDataType(dwordDt, 8, dtmImpl); dtmImpl->addDataType(dwordPtr);

        auto* node = new StructureDataType(CategoryPath::ROOT(), "Node", 0, dtmImpl);
        node->add(dwordDt, "id", "");
        node->add(dwordPtr, "next", "");  // pointer field referencing DWORD*
        dtmImpl->addDataType(node);

        auto* origField0 = node->getComponent(0); // id field
        auto* origField1 = node->getComponent(1); // next field (DWORD*)
        TEST("node.pre_f0_is_dword", origField0 && origField0->getDataType() == dwordDt);
        TEST("node.pre_f1_is_dword_ptr", origField1 && origField1->getDataType() == dwordPtr);

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restNode = restDtm ? dynamic_cast<StructureDataType*>(restDtm->getDataType(CategoryPath::ROOT(), "Node")) : nullptr;
        TEST("node.restored", restNode != nullptr);
        if (restNode && restNode->getNumComponents() >= 2) {
            auto* f0 = restNode->getComponent(0);
            auto* f1 = restNode->getComponent(1);
            TEST("node.rf0_name", f0 && f0->getFieldName() == "id");
            TEST("node.rf0_is_dword", f0 && f0->getDataType() && f0->getDataType()->getName() == "dword");
            TEST("node.rf1_name", f1 && f1->getFieldName() == "next");
            if (f1 && f1->getDataType()) {
                std::cout << "  Field 'next' type: " << f1->getDataType()->getName() << "\n";
                auto* f1Ptr = dynamic_cast<Pointer*>(f1->getDataType());
                if (f1Ptr) {
                    auto* ptrTarget = f1Ptr->getDataType();
                    std::cout << "  Field 'next' pointer target: " << (ptrTarget ? ptrTarget->getName() : "null") << "\n";
                    TEST("node.rf1_pointer_target_dword", ptrTarget && ptrTarget->getName() == "dword");
                } else {
                    std::cout << "  Field 'next' is not a Pointer\n";
                    TEST("node.rf1_is_pointer", false);
                }
            } else {
                TEST("node.rf1_exists", false);
            }
        }
    }

    // ================================================================
    // TEST 6: Circular self-referential struct (Node { Node* next })
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("circular_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* node = new StructureDataType(CategoryPath::ROOT(), "Node", 0, dtmImpl);
        // Add integer field first (no dependency)
        auto* intDt = dtmImpl->getDataType(CategoryPath::ROOT(), "int");
        node->add(intDt, "value", "");
        // Add self-referential pointer field — depends on Node which doesn't exist yet at this point
        // But add() only stores the DataType* pointer, so it works
        auto* nodePtr = new PointerDataType(node, 8, dtmImpl);
        dtmImpl->addDataType(nodePtr);
        node->add(nodePtr, "next", "");
        dtmImpl->addDataType(node);

        // Verify pre-snapshot
        TEST("circ.pre_node_exists", node != nullptr);
        TEST("circ.pre_node_f0_int", node->getComponent(0)->getDataType() == intDt);
        auto* f1Type = node->getComponent(1)->getDataType();
        auto* f1Ptr = dynamic_cast<Pointer*>(f1Type);
        TEST("circ.pre_node_f1_is_ptr", f1Ptr != nullptr);
        if (f1Ptr) {
            auto* ptrTarget = f1Ptr->getDataType();
            TEST("circ.pre_pointer_to_self", ptrTarget == node);
            std::cout << "  Circular: Node.value=int, Node.next=Node* -> target="
                      << (ptrTarget ? ptrTarget->getName() : "null") << "\n";
        }

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restNode = restDtm ? dynamic_cast<StructureDataType*>(
            restDtm->getDataType(CategoryPath::ROOT(), "Node")) : nullptr;
        TEST("circ.restored_node", restNode != nullptr);

        if (restNode && restNode->getNumComponents() >= 2) {
            auto* rf0 = restNode->getComponent(0);
            TEST("circ.rf0_is_int", rf0 && rf0->getDataType() &&
                 rf0->getDataType()->getName() == "int");

            auto* rf1 = restNode->getComponent(1);
            TEST("circ.rf1_exists", rf1 != nullptr);
            auto* rf1Ptr = rf1 ? dynamic_cast<Pointer*>(rf1->getDataType()) : nullptr;
            TEST("circ.rf1_is_ptr", rf1Ptr != nullptr);

            if (rf1Ptr) {
                auto* rf1Target = rf1Ptr->getDataType();
                std::cout << "  RESTORED: Node.value=int, Node.next=Node* -> target="
                          << (rf1Target ? rf1Target->getName() : "null") << "\n";
                TEST("circ.rf1_ptr_to_self", rf1Target == restNode);
            }
        }
    }

    // ================================================================
    // TEST 7: Mutual recursion (struct A { B* b } ↔ struct B { A* a })
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("mutual_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* structA = new StructureDataType(CategoryPath::ROOT(), "A", 0, dtmImpl);
        auto* structB = new StructureDataType(CategoryPath::ROOT(), "B", 0, dtmImpl);

        // Create pointers to each other
        auto* ptrToB = new PointerDataType(structB, 8, dtmImpl);
        dtmImpl->addDataType(ptrToB);
        auto* ptrToA = new PointerDataType(structA, 8, dtmImpl);
        dtmImpl->addDataType(ptrToA);

        // A has field pointing to B
        structA->add(ptrToB, "b", "");
        dtmImpl->addDataType(structA);

        // B has field pointing to A
        structB->add(ptrToA, "a", "");
        dtmImpl->addDataType(structB);

        std::cout << "  Mutual: A.b=*B, B.a=*A\n";

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restA = restDtm ? dynamic_cast<StructureDataType*>(
            restDtm->getDataType(CategoryPath::ROOT(), "A")) : nullptr;
        auto* restB = restDtm ? dynamic_cast<StructureDataType*>(
            restDtm->getDataType(CategoryPath::ROOT(), "B")) : nullptr;
        TEST("mut.restored_A", restA != nullptr);
        TEST("mut.restored_B", restB != nullptr);

        // A.b → *B → B
        if (restA && restA->getNumComponents() >= 1) {
            auto* f0 = restA->getComponent(0);
            auto* f0Ptr = f0 ? dynamic_cast<Pointer*>(f0->getDataType()) : nullptr;
            TEST("mut.A_b_is_ptr", f0Ptr != nullptr);
            TEST("mut.A_b_target_is_B", f0Ptr && f0Ptr->getDataType() == restB);
        }

        // B.a → *A → A
        if (restB && restB->getNumComponents() >= 1) {
            auto* f0 = restB->getComponent(0);
            auto* f0Ptr = f0 ? dynamic_cast<Pointer*>(f0->getDataType()) : nullptr;
            TEST("mut.B_a_is_ptr", f0Ptr != nullptr);
            TEST("mut.B_a_target_is_A", f0Ptr && f0Ptr->getDataType() == restA);
        }
    }

    // ================================================================
    // TEST 8: Triple-pointer chain (int → int* → int** → int***)
    // ================================================================
    {
        ProgramDB prog;
        prog.initialize("chain_test", nullptr, nullptr);
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(prog.getDataTypeManager());

        auto* intDt = dtmImpl->getDataType(CategoryPath::ROOT(), "int");

        auto* intPtr = new PointerDataType(intDt, 8, dtmImpl);
        dtmImpl->addDataType(intPtr);
        auto* intPtrPtr = new PointerDataType(intPtr, 8, dtmImpl);
        dtmImpl->addDataType(intPtrPtr);
        auto* intPtrPtrPtr = new PointerDataType(intPtrPtr, 8, dtmImpl);
        dtmImpl->addDataType(intPtrPtrPtr);

        std::cout << "  Chain: int → int* → int** → int***\n";

        auto snapData = storage::SnapshotWriter::serialize(prog);
        auto restored = storage::SnapshotReader::deserialize(snapData.data(), snapData.size());

        auto* restDtm = restored->getDataTypeManager();
        auto* restDt = restDtm ? restDtm->getDataType(CategoryPath::ROOT(), intPtrPtrPtr->getName()) : nullptr;
        TEST("ch.ptr3_restored", restDt != nullptr);

        auto* p3 = dynamic_cast<Pointer*>(restDt);
        TEST("ch.p3_is_ptr", p3 != nullptr);
        if (p3) {
            auto* p3t = p3->getDataType();  // int**
            auto* p2 = dynamic_cast<Pointer*>(p3t);
            TEST("ch.p2_is_ptr", p2 != nullptr);
            if (p2) {
                auto* p2t = p2->getDataType();  // int*
                auto* p1 = dynamic_cast<Pointer*>(p2t);
                TEST("ch.p1_is_ptr", p1 != nullptr);
                if (p1) {
                    TEST("ch.p1_target_is_int", p1->getDataType() && p1->getDataType()->getName() == "int");
                }
            }
        }
    }

    std::cout << "\n=== Gap Verification Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}
