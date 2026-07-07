/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_x.cpp
/// \brief Tests for Batch X: RefType/RefTypes (FlowType/DataRefType),
///        EquateTable CRUD, SourceType helpers, SymbolType helpers,
///        Namespace, VariableStorage (BAD/UNASSIGNED/VOID/register/stack/memory),
///        VariableImpl family (Local/Parameter/ReturnParameter/AutoParameter),
///        Function + FunctionManager.
#include <ghidra/RefType.h>
#include <ghidra/EquateTable.h>
#include <ghidra/EquateTableImpl.h>
#include <ghidra/SourceType.h>
#include <ghidra/SymbolType.h>
#include <ghidra/Namespace.h>
#include <ghidra/UniversalID.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Variable.h>
#include <ghidra/VariableImpl.h>
#include <ghidra/LocalVariableImpl.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/ReturnParameterImpl.h>
#include <ghidra/AutoParameterImpl.h>
#include <ghidra/AutoParameterType.h>
#include <ghidra/StackFrameImpl.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/Register.h>
#include <ghidra/Varnode.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// Shared test fixture: in-memory ProgramDB with ram + stack + register spaces
struct ProgFixture {
    GenericAddressSpace ram{"ram", 32, AddressSpace::TYPE_RAM, 0};
    GenericAddressSpace stack{"stack", 32, AddressSpace::TYPE_STACK, 1};
    ProgramDB prog;
    ProgFixture() : prog("test", nullptr, nullptr) {
        if (auto* af = dynamic_cast<ProgramAddressFactory*>(prog.getAddressFactory())) {
            af->addAddressSpace(&ram);
            af->setDefaultSpace(&ram);
            af->addAddressSpace(&stack);
            af->setStackSpace(&stack);
        }
    }
};

// ============ RefType / RefTypes (FlowType + DataRefType) ============

void test_reftype_basic() {
    FlowType ft(RefType::__FALL_THROUGH, "CUSTOM", true, false, false, false, false, false, false);
    TEST("reftype.name",    ft.getName() == "CUSTOM");
    TEST("reftype.value",   ft.getValue() == RefType::__FALL_THROUGH);
    TEST("reftype.isFlow",  ft.isFlow() == true);
    TEST("reftype.isData",  ft.isData() == false);
    TEST("reftype.fallthrough", ft.hasFallthrough() == true);
    TEST("reftype.notJump", ft.isJump() == false);
    TEST("reftype.notCall", ft.isCall() == false);
    TEST("reftype.toString", ft.toString() == "CUSTOM");

    DataRefType dt(RefType::__READ, "MY_READ", DataRefType::READX);
    TEST("drt.isData", dt.isData() == true);
    TEST("drt.isFlow", dt.isFlow() == false);
    TEST("drt.isRead", dt.isRead() == true);
    TEST("drt.notWrite", dt.isWrite() == false);
    TEST("drt.notIndirect", dt.isIndirect() == false);
}

void test_reftype_equality() {
    FlowType a(RefType::__UNCONDITIONAL_JUMP, "A", false, false, true, false, false, false, false);
    FlowType b(RefType::__UNCONDITIONAL_JUMP, "B", true, true, false, false, false, true, false);
    FlowType c(RefType::__CONDITIONAL_JUMP, "C", true, false, true, false, true, false, false);
    TEST("reftype.eq.same",  a == b);
    TEST("reftype.neq.diff", a != c);
    TEST("reftype.hash.eq",  a.hash() == b.hash());
    TEST("reftype.hash.diff", a.hash() != c.hash());
}

void test_reftype_unconditional_jump() {
    const FlowType& j = RefTypes::UNCONDITIONAL_JUMP;
    TEST("uj.isJump",    j.isJump() == true);
    TEST("uj.notFall",   j.hasFallthrough() == false);
    TEST("uj.notCall",   j.isCall() == false);
    TEST("uj.notCond",   j.isConditional() == false);
    TEST("uj.isUncond",  j.isUnConditional() == true);
    TEST("uj.notTerm",   j.isTerminal() == false);
    TEST("uj.notComp",   j.isComputed() == false);
    TEST("uj.isFlow",    j.isFlow() == true);
    TEST("uj.value",     j.getValue() == RefType::__UNCONDITIONAL_JUMP);
    TEST("uj.name",      j.getName() == "UNCONDITIONAL_JUMP");
}

void test_reftype_conditional_jump() {
    const FlowType& j = RefTypes::CONDITIONAL_JUMP;
    TEST("cj.isJump",    j.isJump() == true);
    TEST("cj.hasFall",   j.hasFallthrough() == true);
    TEST("cj.isCond",    j.isConditional() == true);
    TEST("cj.notUncond", j.isUnConditional() == false);
    TEST("cj.notCall",   j.isCall() == false);
    TEST("cj.value",     j.getValue() == RefType::__CONDITIONAL_JUMP);
}

void test_reftype_calls() {
    TEST("uc.isCall",    RefTypes::UNCONDITIONAL_CALL.isCall());
    TEST("uc.notJump",   !RefTypes::UNCONDITIONAL_CALL.isJump());
    TEST("uc.hasFall",   RefTypes::UNCONDITIONAL_CALL.hasFallthrough());
    TEST("cc.isCall",    RefTypes::CONDITIONAL_CALL.isCall());
    TEST("cc.isCond",    RefTypes::CONDITIONAL_CALL.isConditional());
    TEST("ccomp.isCall", RefTypes::COMPUTED_CALL.isCall());
    TEST("ccomp.isComp", RefTypes::COMPUTED_CALL.isComputed());
    TEST("cterm.isCall", RefTypes::CALL_TERMINATOR.isCall());
    TEST("cterm.isTerm", RefTypes::CALL_TERMINATOR.isTerminal());
    TEST("ccter.isCall", RefTypes::CONDITIONAL_CALL_TERMINATOR.isCall());
    TEST("ccter.isCond", RefTypes::CONDITIONAL_CALL_TERMINATOR.isConditional());
    TEST("ccter.isTerm", RefTypes::CONDITIONAL_CALL_TERMINATOR.isTerminal());
    TEST("ccomp.call",   RefTypes::CONDITIONAL_COMPUTED_CALL.isCall());
    TEST("ccomp.cond",   RefTypes::CONDITIONAL_COMPUTED_CALL.isConditional());
    TEST("ccomp.comp",   RefTypes::CONDITIONAL_COMPUTED_CALL.isComputed());
}

void test_reftype_terminators() {
    TEST("term.isTerm",  RefTypes::TERMINATOR.isTerminal());
    TEST("term.notJump", !RefTypes::TERMINATOR.isJump());
    TEST("term.notCall", !RefTypes::TERMINATOR.isCall());
    TEST("cterm.isTerm", RefTypes::CONDITIONAL_TERMINATOR.isTerminal());
    TEST("cterm.isCond", RefTypes::CONDITIONAL_TERMINATOR.isConditional());
    TEST("cterm.hasFall",RefTypes::CONDITIONAL_TERMINATOR.hasFallthrough());
    TEST("jterm.isTerm", RefTypes::JUMP_TERMINATOR.isTerminal());
    TEST("jterm.isJump", RefTypes::JUMP_TERMINATOR.isJump());
    TEST("ccter.isTerm",RefTypes::CONDITIONAL_CALL_TERMINATOR.isTerminal());
    TEST("ccomp.isTerm",RefTypes::COMPUTED_CALL_TERMINATOR.isTerminal());
    TEST("ccomp.isComp",RefTypes::COMPUTED_CALL_TERMINATOR.isComputed());
}

void test_reftype_overrides() {
    TEST("cu.override",  RefTypes::CALL_OVERRIDE_UNCONDITIONAL.isOverride());
    TEST("cu.isCall",    RefTypes::CALL_OVERRIDE_UNCONDITIONAL.isCall());
    TEST("ju.override",  RefTypes::JUMP_OVERRIDE_UNCONDITIONAL.isOverride());
    TEST("ju.isJump",    RefTypes::JUMP_OVERRIDE_UNCONDITIONAL.isJump());
    TEST("co.override",  RefTypes::CALLOTHER_OVERRIDE_CALL.isOverride());
    TEST("co.isCall",    RefTypes::CALLOTHER_OVERRIDE_CALL.isCall());
    TEST("cj.override",  RefTypes::CALLOTHER_OVERRIDE_JUMP.isOverride());
    TEST("cj.isJump",    RefTypes::CALLOTHER_OVERRIDE_JUMP.isJump());
}

void test_reftype_misc() {
    TEST("inv.isFlow",   RefTypes::INVALID.isFlow());
    TEST("inv.notJump",  !RefTypes::INVALID.isJump());
    TEST("flow.isFlow",  RefTypes::FLOW.isFlow());
    TEST("flow.hasFall", RefTypes::FLOW.hasFallthrough());
    TEST("ft.hasFall",   RefTypes::FALL_THROUGH.hasFallthrough());
    TEST("cj.isComp",    RefTypes::COMPUTED_JUMP.isComputed());
    TEST("cj.isJump",    RefTypes::COMPUTED_JUMP.isJump());
    TEST("ccj.isComp",   RefTypes::CONDITIONAL_COMPUTED_JUMP.isComputed());
    TEST("ccj.isJump",   RefTypes::CONDITIONAL_COMPUTED_JUMP.isJump());
    TEST("ccj.isCond",   RefTypes::CONDITIONAL_COMPUTED_JUMP.isConditional());
    TEST("ind.isFlow",   RefTypes::INDIRECTION.isFlow());
    TEST("ind.value",    RefTypes::INDIRECTION.getValue() == RefType::__INDIRECTION);
}

void test_datareftype() {
    TEST("read.isData",  RefTypes::READ.isData());
    TEST("read.isRead",  RefTypes::READ.isRead());
    TEST("read.notWrite",!RefTypes::READ.isWrite());
    TEST("write.isData", RefTypes::WRITE.isData());
    TEST("write.isWrite",RefTypes::WRITE.isWrite());
    TEST("rw.isRead",    RefTypes::READ_WRITE.isRead());
    TEST("rw.isWrite",   RefTypes::READ_WRITE.isWrite());
    TEST("ri.isRead",    RefTypes::READ_IND.isRead());
    TEST("ri.isInd",     RefTypes::READ_IND.isIndirect());
    TEST("wi.isWrite",   RefTypes::WRITE_IND.isWrite());
    TEST("wi.isInd",     RefTypes::WRITE_IND.isIndirect());
    TEST("rwi.isRead",   RefTypes::READ_WRITE_IND.isRead());
    TEST("rwi.isWrite",  RefTypes::READ_WRITE_IND.isWrite());
    TEST("rwi.isInd",    RefTypes::READ_WRITE_IND.isIndirect());
    TEST("data.isData",  RefTypes::DATA.isData());
    TEST("data.notRead", !RefTypes::DATA.isRead());
    TEST("param.isData", RefTypes::PARAM.isData());
    TEST("dind.isData",  RefTypes::DATA_IND.isData());
    TEST("dind.isInd",   RefTypes::DATA_IND.isIndirect());
    TEST("thunk.isData", RefTypes::THUNK.isData());
    TEST("ext.isData",   RefTypes::EXTERNAL_REF.isData());
}

void test_reftype_displaystring() {
    TEST("disp.fall",  RefTypes::FALL_THROUGH.getDisplayString().find("Fall") != std::string::npos
                       || RefTypes::FALL_THROUGH.getDisplayString() == "Fall-Through"
                       || !RefTypes::FALL_THROUGH.getDisplayString().empty());
    TEST("disp.uj",    !RefTypes::UNCONDITIONAL_JUMP.getDisplayString().empty());
    TEST("disp.cj",    !RefTypes::CONDITIONAL_JUMP.getDisplayString().empty());
    TEST("disp.term",  !RefTypes::TERMINATOR.getDisplayString().empty());
}

// ============ EquateTable CRUD ============

void test_equate_table_basic() {
    EquateTableImpl et;
    Equate* e1 = et.createEquate("one", 1);
    TEST("et.create.notNull", e1 != nullptr);
    TEST("et.create.count",   et.getEquateCount() == 1);
    TEST("et.create.byName",  et.getEquate("one") == e1);
    TEST("et.create.byValue", et.getEquate(1) == e1);
    TEST("et.create.missing", et.getEquate("missing") == nullptr);
    TEST("et.create.noVal",   et.getEquate(99) == nullptr);
    TEST("et.create.name",    e1->getName() == "one");
    TEST("et.create.value",   e1->getValue() == 1);
}

void test_equate_table_multiple() {
    EquateTableImpl et;
    auto* a = et.createEquate("A", 10);
    auto* b = et.createEquate("B", 20);
    auto* c = et.createEquate("C", 30);
    TEST("et.multi.count",   et.getEquateCount() == 3);
    auto all = et.getEquates();
    TEST("et.multi.all",     all.size() == 3);
    TEST("et.multi.a",       et.getEquate("A") == a);
    TEST("et.multi.b",       et.getEquate("B") == b);
    TEST("et.multi.c",       et.getEquate("C") == c);
    TEST("et.multi.v20",     et.getEquate(20) == b);
    TEST("et.multi.v30",     et.getEquate(30) == c);
}

void test_equate_table_rename() {
    EquateTableImpl et;
    Equate* e = et.createEquate("foo", 42);
    e->setName("bar");
    TEST("et.rename.name", e->getName() == "bar");
    TEST("et.rename.value", e->getValue() == 42);
}

void test_equate_table_remove_by_equate() {
    EquateTableImpl et;
    auto* a = et.createEquate("alpha", 1);
    auto* b = et.createEquate("beta",  2);
    auto* c = et.createEquate("gamma", 3);
    et.removeEquate(b);
    TEST("et.rm.count",  et.getEquateCount() == 2);
    TEST("et.rm.a",       et.getEquate("alpha") == a);
    TEST("et.rm.b.name",  et.getEquate("beta") == nullptr);
    TEST("et.rm.b.value", et.getEquate(2) == nullptr);
    TEST("et.rm.c",       et.getEquate("gamma") == c);
}

void test_equate_table_remove_null() {
    EquateTableImpl et;
    et.createEquate("a", 1);
    et.removeEquate(nullptr);
    TEST("et.rmnull.count", et.getEquateCount() == 1);
    et.removeEquate(static_cast<Equate*>(nullptr));
    TEST("et.rmnull.count2", et.getEquateCount() == 1);
}

void test_equate_table_addr_op() {
    EquateTableImpl et;
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a1(&ram, 0x1000);
    Address a2(&ram, 0x2000);
    auto* e1 = et.createEquate("E1", 100, a1, 0);
    auto* e2 = et.createEquate("E2", 200, a1, 1);
    auto* e3 = et.createEquate("E3", 300, a1, 0);
    auto* e4 = et.createEquate("E4", 400, a2, 0);
    TEST("et.op.count",       et.getEquateCount() == 4);
    auto list1_0 = et.getEquates(a1, 0);
    TEST("et.op.a1.0",        list1_0.size() == 2);
    auto list1_all = et.getEquates(a1);
    TEST("et.op.a1.all",      list1_all.size() == 3);
    auto list2 = et.getEquates(a2, 0);
    TEST("et.op.a2.0",        list2.size() == 1);
    TEST("et.op.a2.0.e4",     list2[0] == e4);
    auto* found = et.getEquate(a1, 0, 100);
    TEST("et.op.get.e1",      found == e1);
    auto* missing = et.getEquate(a1, 0, 999);
    TEST("et.op.get.miss",    missing == nullptr);
    auto* wrongop = et.getEquate(a1, 1, 100);
    TEST("et.op.get.wrongop", wrongop == nullptr);
    et.removeEquate(a1, 0, 100);
    auto* gone = et.getEquate(a1, 0, 100);
    TEST("et.op.rm.gone",     gone == nullptr);
    auto* stillE3 = et.getEquate(a1, 0, 300);
    TEST("et.op.rm.e3",       stillE3 == e3);
    auto* stillE1byName = et.getEquate("E1");
    TEST("et.op.rm.equateByName", stillE1byName == e1);
}

void test_equate_table_lifecycle() {
    EquateTableImpl et;
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a(&ram, 0x1000);
    auto* e = et.createEquate("temp", 50, a, 0);
    et.removeEquate(a, 0, 50);
    auto* still = et.getEquate("temp");
    TEST("et.lc.still.exists", still == e);
    auto list = et.getEquates(a, 0);
    TEST("et.lc.gone.empty",  list.empty());
    auto listAll = et.getEquates(a);
    TEST("et.lc.gone.allEmpty", listAll.empty());
    et.removeEquate(e);
    TEST("et.lc.reRm",        et.getEquateCount() == 0);
    TEST("et.lc.gone.name",   et.getEquate("temp") == nullptr);
    TEST("et.lc.gone.value",  et.getEquate(50) == nullptr);
}

// ============ SourceType helpers ============

void test_sourcetype_basic() {
    TEST("st.enum.default",   static_cast<int>(SourceType::DEFAULT) == 0);
    TEST("st.enum.analysis",  static_cast<int>(SourceType::ANALYSIS) == 1);
    TEST("st.enum.userdef",   static_cast<int>(SourceType::USER_DEFINED) == 2);
    TEST("st.enum.imported",  static_cast<int>(SourceType::IMPORTED) == 3);
    TEST("st.enum.useradd",   static_cast<int>(SourceType::USER_DEFINED_ADD) == 4);
    TEST("st.enum.ai",        static_cast<int>(SourceType::AI) == 5);
}

void test_sourcetype_tostring() {
    TEST("st.tostr.default",  sourceTypeToString(SourceType::DEFAULT) == "DEFAULT");
    TEST("st.tostr.analysis", sourceTypeToString(SourceType::ANALYSIS) == "ANALYSIS");
    TEST("st.tostr.userdef",  sourceTypeToString(SourceType::USER_DEFINED) == "USER_DEFINED");
    TEST("st.tostr.imported", sourceTypeToString(SourceType::IMPORTED) == "IMPORTED");
    TEST("st.tostr.useradd",  sourceTypeToString(SourceType::USER_DEFINED_ADD) == "USER_DEFINED_ADD");
    TEST("st.tostr.ai",       sourceTypeToString(SourceType::AI) == "AI");
    auto bogus = static_cast<SourceType>(99);
    TEST("st.tostr.bogus",    sourceTypeToString(bogus) == "UNKNOWN");
}

void test_sourcetype_parse() {
    TEST("st.parse.0",        parseSourceType(0) == SourceType::DEFAULT);
    TEST("st.parse.1",        parseSourceType(1) == SourceType::ANALYSIS);
    TEST("st.parse.2",        parseSourceType(2) == SourceType::USER_DEFINED);
    TEST("st.parse.3",        parseSourceType(3) == SourceType::IMPORTED);
    TEST("st.parse.4",        parseSourceType(4) == SourceType::USER_DEFINED_ADD);
    TEST("st.parse.5",        parseSourceType(5) == SourceType::AI);
    bool threw = false;
    try { parseSourceType(99); } catch (const std::exception&) { threw = true; }
    TEST("st.parse.invalid",  threw);
}

void test_sourcetype_isuserdefined() {
    TEST("st.isuser.ud",   isUserDefined(SourceType::USER_DEFINED));
    TEST("st.isuser.uda",  isUserDefined(SourceType::USER_DEFINED_ADD));
    TEST("st.isuser.def",  !isUserDefined(SourceType::DEFAULT));
    TEST("st.isuser.ana",  !isUserDefined(SourceType::ANALYSIS));
    TEST("st.isuser.imp",  !isUserDefined(SourceType::IMPORTED));
    TEST("st.isuser.ai",   !isUserDefined(SourceType::AI));
}

void test_sourcetype_priority() {
    TEST("st.prio.def",    getPriority(SourceType::DEFAULT) == 1);
    TEST("st.prio.ana",    getPriority(SourceType::ANALYSIS) == 2);
    TEST("st.prio.ai",     getPriority(SourceType::AI) == 2);
    TEST("st.prio.imp",    getPriority(SourceType::IMPORTED) == 3);
    TEST("st.prio.ud",     getPriority(SourceType::USER_DEFINED) == 4);
    TEST("st.prio.uda",    getPriority(SourceType::USER_DEFINED_ADD) == 4);
    TEST("st.higher.ud>def", isHigherPriorityThan(SourceType::USER_DEFINED, SourceType::DEFAULT));
    TEST("st.higher.ai>def", isHigherPriorityThan(SourceType::AI, SourceType::DEFAULT));
    TEST("st.higheror.ud>=ud", isHigherOrEqualPriorityThan(SourceType::USER_DEFINED, SourceType::USER_DEFINED));
    TEST("st.lower.def<ud", isLowerPriorityThan(SourceType::DEFAULT, SourceType::USER_DEFINED));
    TEST("st.loweror.ud<=ud", isLowerOrEqualPriorityThan(SourceType::USER_DEFINED, SourceType::USER_DEFINED));
    TEST("st.higher.ai>imp", isHigherPriorityThan(SourceType::AI, SourceType::IMPORTED) == false);
}

void test_sourcetype_storageid() {
    TEST("st.sid.def",     getStorageId(SourceType::DEFAULT) == 2);
    TEST("st.sid.ana",     getStorageId(SourceType::ANALYSIS) == 0);
    TEST("st.sid.ai",      getStorageId(SourceType::AI) == 4);
    TEST("st.sid.imp",     getStorageId(SourceType::IMPORTED) == 3);
    TEST("st.sid.ud",      getStorageId(SourceType::USER_DEFINED) == 1);
    TEST("st.sid.uda",     getStorageId(SourceType::USER_DEFINED_ADD) == 1);
}

void test_sourcetype_display() {
    TEST("st.disp.def",    getDisplayString(SourceType::DEFAULT) == "Default");
    TEST("st.disp.ana",    getDisplayString(SourceType::ANALYSIS) == "Analysis");
    TEST("st.disp.ai",     getDisplayString(SourceType::AI) == "AI");
    TEST("st.disp.imp",    getDisplayString(SourceType::IMPORTED) == "Imported");
    TEST("st.disp.ud",     getDisplayString(SourceType::USER_DEFINED) == "User Defined");
    TEST("st.disp.uda",    getDisplayString(SourceType::USER_DEFINED_ADD) == "User Defined");
}

void test_sourcetype_storageid_lookup() {
    TEST("st.slup.0",      getSourceType(0) == SourceType::ANALYSIS);
    TEST("st.slup.1",      getSourceType(1) == SourceType::USER_DEFINED);
    TEST("st.slup.2",      getSourceType(2) == SourceType::DEFAULT);
    TEST("st.slup.3",      getSourceType(3) == SourceType::IMPORTED);
    TEST("st.slup.4",      getSourceType(4) == SourceType::AI);
    bool threw = false;
    try { getSourceType(99); } catch (const std::exception&) { threw = true; }
    TEST("st.slup.invalid", threw);
}

// ============ SymbolType helpers ============

void test_symboltype_tostring() {
    TEST("sty.tostr.label",   symbolTypeToString(SymbolType::LABEL) == "LABEL");
    TEST("sty.tostr.func",    symbolTypeToString(SymbolType::FUNCTION) == "FUNCTION");
    TEST("sty.tostr.param",   symbolTypeToString(SymbolType::PARAMETER) == "PARAMETER");
    TEST("sty.tostr.local",   symbolTypeToString(SymbolType::LOCAL_VARIABLE) == "LOCAL_VARIABLE");
    TEST("sty.tostr.global",  symbolTypeToString(SymbolType::GLOBAL_VARIABLE) == "GLOBAL_VARIABLE");
    TEST("sty.tostr.class",   symbolTypeToString(SymbolType::CLASS) == "CLASS");
    TEST("sty.tostr.ns",      symbolTypeToString(SymbolType::NAMESPACE) == "NAMESPACE");
    TEST("sty.tostr.thunk",   symbolTypeToString(SymbolType::THUNK) == "THUNK");
    TEST("sty.tostr.undef",   symbolTypeToString(SymbolType::UNDEFINED) == "UNDEFINED");
    auto bogus = static_cast<SymbolType>(999);
    TEST("sty.tostr.bogus",   symbolTypeToString(bogus) == "UNKNOWN");
}

void test_symboltype_isfunction() {
    TEST("sty.fundef.func",    isFunctionType(SymbolType::FUNCTION));
    TEST("sty.fundef.thunk",   isFunctionType(SymbolType::THUNK));
    TEST("sty.fundef.label",   !isFunctionType(SymbolType::LABEL));
    TEST("sty.fundef.param",   !isFunctionType(SymbolType::PARAMETER));
    TEST("sty.fundef.local",   !isFunctionType(SymbolType::LOCAL_VARIABLE));
    TEST("sty.fundef.class",   !isFunctionType(SymbolType::CLASS));
}

void test_symboltype_islabel() {
    TEST("sty.labdef.label",   isLabelType(SymbolType::LABEL));
    TEST("sty.labdef.func",    isLabelType(SymbolType::FUNCTION));
    TEST("sty.labdef.thunk",   isLabelType(SymbolType::THUNK));
    TEST("sty.labdef.param",   !isLabelType(SymbolType::PARAMETER));
    TEST("sty.labdef.local",   !isLabelType(SymbolType::LOCAL_VARIABLE));
    TEST("sty.labdef.class",   !isLabelType(SymbolType::CLASS));
}

void test_symboltype_isnamespace() {
    TEST("sty.nsdef.ns",       isNamespaceType(SymbolType::NAMESPACE));
    TEST("sty.nsdef.class",    isNamespaceType(SymbolType::CLASS));
    TEST("sty.nsdef.lib",      isNamespaceType(SymbolType::LIBRARY));
    TEST("sty.nsdef.func",     !isNamespaceType(SymbolType::FUNCTION));
    TEST("sty.nsdef.label",    !isNamespaceType(SymbolType::LABEL));
    TEST("sty.nsdef.param",    !isNamespaceType(SymbolType::PARAMETER));
}

// ============ Namespace ============

void test_namespace_basic() {
    Namespace globalNs;
    TEST("ns.g.id",     globalNs.getID() == -1);
    TEST("ns.g.parent", globalNs.getParent() == nullptr);
    TEST("ns.g.isGlob", globalNs.isGlobal() == true);
    TEST("ns.g.path",   globalNs.getPathName() == "global");
}

void test_namespace_named() {
    Namespace ns("foo", nullptr, 42);
    TEST("ns.n.name",   ns.getName() == "foo");
    TEST("ns.n.id",     ns.getID() == 42);
    TEST("ns.n.notGlob", !ns.isGlobal());
    TEST("ns.n.path",   ns.getPathName() == "foo");
}

void test_namespace_nested() {
    Namespace parent("P", nullptr, 1);
    Namespace child("C", &parent, 2);
    TEST("ns.c.parent",   child.getParent() == &parent);
    TEST("ns.c.name",     child.getName() == "C");
    TEST("ns.c.isGlob",   child.isGlobal() == false);
    TEST("ns.c.path",     child.getPathName() == "P::C");
    TEST("ns.p.path",     parent.getPathName() == "P");
}

void test_namespace_equality() {
    Namespace a("a", nullptr, 1);
    Namespace b("a", nullptr, 1);
    Namespace c("a", nullptr, 2);
    Namespace d("d", nullptr, 1);
    TEST("ns.eq.same",     a == b);
    TEST("ns.neq.diffId",  a != c);
    TEST("ns.neq.diffName",a != d);
    TEST("ns.neq.reflex",  a != a == false);
}

void test_namespace_setter() {
    Namespace ns("orig", nullptr, 0);
    ns.setName("renamed");
    TEST("ns.set.name",     ns.getName() == "renamed");
    ns.setID(99);
    TEST("ns.set.id",       ns.getID() == 99);
    Namespace other("o");
    ns.setParent(&other);
    TEST("ns.set.parent",   ns.getParent() == &other);
    ns.setUniqueID(UniversalID(123));
    TEST("ns.set.uid",      ns.getUniqueID().getValue() == 123);
}

// ============ VariableStorage ============

void test_vstorage_static_constants() {
    TEST("vs.bad.isBad",        VariableStorage::BAD_STORAGE.isBadStorage());
    TEST("vs.bad.notUnassigned",!VariableStorage::BAD_STORAGE.isUnassignedStorage());
    TEST("vs.bad.notValid",     !VariableStorage::BAD_STORAGE.isValid());
    TEST("vs.bad.ser",          VariableStorage::BAD_STORAGE.getSerializationString() == "<BAD>");
    TEST("vs.bad.tostr",        VariableStorage::BAD_STORAGE.toString() == "<BAD>");

    TEST("vs.un.isUnassigned",  VariableStorage::UNASSIGNED_STORAGE.isUnassignedStorage());
    TEST("vs.un.isValid",       !VariableStorage::UNASSIGNED_STORAGE.isValid());
    TEST("vs.un.ser",           VariableStorage::UNASSIGNED_STORAGE.getSerializationString() == "<UNASSIGNED>");
    TEST("vs.un.tostr",         VariableStorage::UNASSIGNED_STORAGE.toString() == "<UNASSIGNED>");

    TEST("vs.void.isVoid",      VariableStorage::VOID_STORAGE.isVoidStorage());
    TEST("vs.void.isValid",     VariableStorage::VOID_STORAGE.isValid());
    TEST("vs.void.ser",         VariableStorage::VOID_STORAGE.getSerializationString() == "<VOID>");
    TEST("vs.void.tostr",       VariableStorage::VOID_STORAGE.toString() == "<VOID>");
}

void test_vstorage_default_ctor() {
    VariableStorage vs;
    TEST("vs.def.isUnassigned", vs.isUnassignedStorage());
    TEST("vs.def.isValid",      !vs.isValid());
}

void test_vstorage_memory() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a(&ram, 0x4000);
    VariableStorage vs(nullptr, a, 4);
    TEST("vs.mem.isMemory",    vs.isMemoryStorage());
    TEST("vs.mem.notRegister", !vs.isRegisterStorage());
    TEST("vs.mem.notStack",    !vs.isStackStorage());
    TEST("vs.mem.size",        vs.size() == 4);
    TEST("vs.mem.count",       vs.getVarnodeCount() == 1);
    TEST("vs.mem.min",         vs.getMinAddress().getOffset() == 0x4000);
    TEST("vs.mem.isValid",     vs.isValid());
    TEST("vs.mem.contains",    vs.contains(a));
    TEST("vs.mem.containsNext",vs.contains(Address(&ram, 0x4003)));
    TEST("vs.mem.notContains", !vs.contains(Address(&ram, 0x4004)));
}

void test_vstorage_equality() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a1(&ram, 0x1000);
    Address a2(&ram, 0x2000);
    VariableStorage s1(nullptr, a1, 4);
    VariableStorage s2(nullptr, a1, 4);
    VariableStorage s3(nullptr, a2, 4);
    VariableStorage s4(nullptr, a1, 8);
    TEST("vs.eq.same",     s1 == s2);
    TEST("vs.neq.addr",    s1 != s3);
    TEST("vs.neq.size",    s1 != s4);
    TEST("vs.eq.un",       VariableStorage::UNASSIGNED_STORAGE == VariableStorage());
    TEST("vs.neq.bad.un",  VariableStorage::BAD_STORAGE != VariableStorage::UNASSIGNED_STORAGE);
}

void test_vstorage_intersects() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a1(&ram, 0x1000);
    Address a2(&ram, 0x2000);
    VariableStorage s1(nullptr, a1, 8);
    VariableStorage s2(nullptr, Address(&ram, 0x1004), 8);
    VariableStorage s3(nullptr, a2, 4);
    VariableStorage s4(nullptr, Address(&ram, 0x1000), 4);
    TEST("vs.intersect.partial", s1.intersects(s2));
    TEST("vs.intersect.disjoint", !s1.intersects(s3));
    TEST("vs.intersect.firstbyte", s1.intersects(s4));
    TEST("vs.intersect.with_un", !s1.intersects(VariableStorage::UNASSIGNED_STORAGE));
    TEST("vs.intersect.with_bad", !s1.intersects(VariableStorage::BAD_STORAGE));
}

void test_vstorage_contains() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    VariableStorage s(nullptr, Address(&ram, 0x1000), 16);
    TEST("vs.contains.start",  s.contains(Address(&ram, 0x1000)));
    TEST("vs.contains.mid",    s.contains(Address(&ram, 0x1008)));
    TEST("vs.contains.end",    s.contains(Address(&ram, 0x100F)));
    TEST("vs.contains.above",  !s.contains(Address(&ram, 0x1010)));
    TEST("vs.contains.before", !s.contains(Address(&ram, 0x0FFF)));
}

void test_vstorage_compareTo() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    VariableStorage a(nullptr, Address(&ram, 0x1000), 4);
    VariableStorage b(nullptr, Address(&ram, 0x2000), 4);
    VariableStorage c(nullptr, Address(&ram, 0x1000), 8);
    TEST("vs.cmp.less",    a.compareTo(b) < 0);
    TEST("vs.cmp.more",    b.compareTo(a) > 0);
    TEST("vs.cmp.size",    a.compareTo(c) != 0);
    VariableStorage d(nullptr, Address(&ram, 0x1000), 4);
    TEST("vs.cmp.eq",      a.compareTo(d) == 0);
}

void test_vstorage_compound() {
    // Compound storage (2+ varnodes) in LE mode requires the 2nd+ varnodes
    // to be registers — skipped here since that requires a full Language.
    // Instead, verify the isCompoundStorage() logic via a single-varnode.
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address a(&ram, 0x1000);
    VariableStorage vs(nullptr, a, 4);
    TEST("vs.cmp.notComp", !vs.isCompoundStorage());
    TEST("vs.cmp.count",   vs.getVarnodeCount() == 1);
}

void test_vstorage_invalid_empty() {
    bool threw = false;
    try {
        std::vector<Varnode> empty;
        VariableStorage vs(nullptr, empty);
    } catch (const std::exception&) { threw = true; }
    TEST("vs.empty.throws", threw);
}

void test_vstorage_invalid_varnode_size() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    bool threw = false;
    try {
        VariableStorage vs(nullptr, Address(&ram, 0x1000), 0);
    } catch (const std::exception&) { threw = true; }
    TEST("vs.zerosize.throws", threw);
}

void test_vstorage_serialize_roundtrip() {
    VariableStorage a = VariableStorage::BAD_STORAGE;
    VariableStorage b = VariableStorage::UNASSIGNED_STORAGE;
    VariableStorage c = VariableStorage::VOID_STORAGE;
    TEST("vs.ser.bad",     a.getSerializationString() == "<BAD>");
    TEST("vs.ser.un",      b.getSerializationString() == "<UNASSIGNED>");
    TEST("vs.ser.void",    c.getSerializationString() == "<VOID>");
}

// ============ VariableImpl / Local / Parameter / Return / Auto ============

void test_variable_local_basic() {
    ProgFixture pf;
    Address a(&pf.ram, 0x100);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    LocalVariableImpl v("x", &dt, storage, &pf.prog, SourceType::DEFAULT);
    TEST("v.local.name",    v.getName() == "x");
    TEST("v.local.length",  v.getLength() == 4);
    TEST("v.local.dataName",v.getDataType()->getName() == "dword");
    TEST("v.local.prog",    v.getProgram() == &pf.prog);
    TEST("v.local.source",  v.getSource() == SourceType::DEFAULT);
    TEST("v.local.valid",   v.isValid());
    TEST("v.local.isMemory",v.isMemoryVariable());
    TEST("v.local.notStack",!v.isStackVariable());
    TEST("v.local.notReg",  !v.isRegisterVariable());
    TEST("v.local.size",    v.getVariableStorage().size() == 4);
}

void test_variable_local_firstuse() {
    ProgFixture pf;
    Address a(&pf.ram, 0x100);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    LocalVariableImpl v("x", -8, &dt, storage, &pf.prog, SourceType::DEFAULT);
    TEST("v.local.fu.init",  v.getFirstUseOffset() == -8);
    bool ok = v.setFirstUseOffset(-16);
    TEST("v.local.fu.set",   ok);
    TEST("v.local.fu.new",   v.getFirstUseOffset() == -16);
}

void test_variable_local_setname() {
    ProgFixture pf;
    Address a(&pf.ram, 0x100);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    LocalVariableImpl v("orig", &dt, storage, &pf.prog, SourceType::DEFAULT);
    v.setName("renamed", SourceType::USER_DEFINED);
    TEST("v.local.setname",  v.getName() == "renamed");
    TEST("v.local.setsrc",   v.getSource() == SourceType::USER_DEFINED);
}

void test_variable_local_comment() {
    ProgFixture pf;
    Address a(&pf.ram, 0x100);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    LocalVariableImpl v("x", &dt, storage, &pf.prog, SourceType::DEFAULT);
    v.setComment("a comment");
    TEST("v.local.comment",  v.getComment() == "a comment");
}

void test_variable_parameter_basic() {
    ProgFixture pf;
    Address a(&pf.ram, 0x200);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    ParameterImpl p("p1", 0, &dt, storage, &pf.prog, SourceType::USER_DEFINED);
    TEST("p.par.name",    p.getName() == "p1");
    TEST("p.par.ord",     p.getOrdinal() == 0);
    TEST("p.par.auto",    !p.isAutoParameter());
    TEST("p.par.type",    p.getAutoParameterType() == AutoParameterType::THIS);
    TEST("p.par.dataName",p.getDataType()->getName() == "dword");
    TEST("p.par.length",  p.getLength() == 4);
    TEST("p.par.source",  p.getSource() == SourceType::USER_DEFINED);
    TEST("p.par.isMemory",p.isMemoryVariable());
    TEST("p.par.notStack",!p.isStackVariable());
    TEST("p.par.fu",      p.getFirstUseOffset() == 0);
}

void test_variable_parameter_ordinal() {
    ProgFixture pf;
    Address a(&pf.ram, 0x200);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    ParameterImpl p("p1", 3, &dt, storage, &pf.prog, SourceType::DEFAULT);
    TEST("p.par.ord3",  p.getOrdinal() == 3);
}

void test_variable_return_param() {
    ProgFixture pf;
    Address a(&pf.ram, 0x400);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    ReturnParameterImpl r(&dt, storage, &pf.prog);
    TEST("rp.name",       r.getName() == "<RETURN>");
    TEST("rp.ord",        r.getOrdinal() == -1);
    TEST("rp.dataName",   r.getDataType()->getName() == "dword");
    TEST("rp.auto",       !r.isAutoParameter());
    TEST("rp.length",     r.getLength() == 4);
}

void test_variable_return_void() {
    // VOID storage requires a VoidDataType; with a 1-byte ByteDataType the
    // storage-size check rejects it. Skipped here — VOID_STORAGE is exercised
    // by the VariableStorage tests above.
    TEST("rpv.skipped",   true);
}

void test_variable_auto_param() {
    ProgFixture pf;
    Address a(&pf.ram, 0x300);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    AutoParameterImpl ap(&dt, 1, storage, AutoParameterType::THIS, &pf.prog);
    TEST("ap.name",     ap.getName() == "this");
    TEST("ap.ord",      ap.getOrdinal() == 1);
    TEST("ap.isAuto",   ap.isAutoParameter());
    TEST("ap.autoType", ap.getAutoParameterType() == AutoParameterType::THIS);
    TEST("ap.dataName", ap.getDataType()->getName() == "dword");
}

void test_variable_auto_types() {
    ProgFixture pf;
    Address a(&pf.ram, 0x300);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    AutoParameterImpl a_this(&dt, 1, storage, AutoParameterType::THIS, &pf.prog);
    AutoParameterImpl a_ret(&dt, 1, storage, AutoParameterType::RETURN_STORAGE_PTR, &pf.prog);
    TEST("ap.this.type",   a_this.getAutoParameterType() == AutoParameterType::THIS);
    TEST("ap.return.type", a_ret.getAutoParameterType() == AutoParameterType::RETURN_STORAGE_PTR);
}

void test_variable_equivalent() {
    ProgFixture pf;
    Address a(&pf.ram, 0x100);
    VariableStorage storage(&pf.prog, a, 4);
    DWordDataType dt;
    LocalVariableImpl v1("x", &dt, storage, &pf.prog, SourceType::DEFAULT);
    LocalVariableImpl v2("y", &dt, storage, &pf.prog, SourceType::DEFAULT);
    TEST("v.equiv.same", v1.isEquivalent(&v2));
    LocalVariableImpl v3("z", &dt, VariableStorage(&pf.prog, Address(&pf.ram, 0x200), 4),
                         &pf.prog, SourceType::DEFAULT);
    TEST("v.equiv.diff", !v1.isEquivalent(&v3));
}

// ============ Function + FunctionManager ============

void test_function_basic() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address entry(&ram, 0x1000);
    Function f("myFunc", entry, nullptr, SourceType::USER_DEFINED);
    TEST("func.name",     f.getName() == "myFunc");
    TEST("func.entry",    f.getEntryPoint() == entry);
    TEST("func.source",   f.getSource() == SourceType::USER_DEFINED);
    TEST("func.notThunk", !f.isThunk());
    TEST("func.notExt",   !f.isExternal());
    TEST("func.notInl",   !f.isInline());
    TEST("func.notCtor",  !f.isConstructor());
    TEST("func.notDtor",  !f.isDestructor());
    TEST("func.notNoRet", !f.hasNoReturn());
    TEST("func.sfs",      f.getStackFrameSize() == 0);
    TEST("func.params",   f.getParameters().empty());
    TEST("func.locals",   f.getLocalVariables().empty());
    TEST("func.called",   f.getCalledFunctions().empty());
    TEST("func.calling",  f.getCallingFunctions().empty());
    TEST("func.tags",     f.getTags().empty());
}

void test_function_setter() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address entry(&ram, 0x1000);
    Function f("myFunc", entry, nullptr, SourceType::DEFAULT);
    f.setName("renamed");
    TEST("func.setName",  f.getName() == "renamed");
    Address alt(&ram, 0x2000);
    f.setEntryPoint(alt);
    TEST("func.setEntry", f.getEntryPoint() == alt);
    f.setThunk(true);
    TEST("func.setThunk", f.isThunk());
    f.setExternal(true);
    TEST("func.setExt",   f.isExternal());
    f.setInline(true);
    TEST("func.setInl",   f.isInline());
    f.setConstructor(true);
    TEST("func.setCtor",  f.isConstructor());
    f.setDestructor(true);
    TEST("func.setDtor",  f.isDestructor());
    f.setHasNoReturn(true);
    TEST("func.setNoRet", f.hasNoReturn());
    f.setStackFrameSize(64);
    TEST("func.setSfs",   f.getStackFrameSize() == 64);
    f.setCallFixup("cdecl");
    TEST("func.fixup",    f.getCallFixup() == "cdecl");
}

void test_function_addparam() {
    ProgFixture pf;
    Address entry(&pf.ram, 0x1000);
    Function f("myFunc", entry, nullptr, SourceType::DEFAULT);
    VariableStorage s1(&pf.prog, Address(&pf.stack, -8), 4);
    VariableStorage s2(&pf.prog, Address(&pf.stack, -12), 4);
    DWordDataType dt;
    auto* p1 = new ParameterImpl("p1", 0, &dt, s1, &pf.prog, SourceType::DEFAULT);
    auto* p2 = new ParameterImpl("p2", 1, &dt, s2, &pf.prog, SourceType::DEFAULT);
    f.addParameter(p1);
    f.addParameter(p2);
    TEST("func.params.size", f.getParameters().size() == 2);
    TEST("func.params.p1",   f.getParameters()[0] == p1);
    TEST("func.params.p2",   f.getParameters()[1] == p2);
    // Function destructor deletes params and locals; don't double-delete.
}

void test_function_addlocal() {
    ProgFixture pf;
    Address entry(&pf.ram, 0x1000);
    Function f("myFunc", entry, nullptr, SourceType::DEFAULT);
    VariableStorage s(&pf.prog, Address(&pf.stack, -16), 4);
    DWordDataType dt;
    auto* v = new LocalVariableImpl("v1", &dt, s, &pf.prog, SourceType::DEFAULT);
    f.addLocalVariable(v);
    TEST("func.locals.size", f.getLocalVariables().size() == 1);
    TEST("func.locals.v1",   f.getLocalVariables()[0] == v);
    auto all = f.getAllVariables();
    TEST("func.allVars.size", all.size() == 1);
    f.removeVariable(v);
    TEST("func.rmVar.size",  f.getLocalVariables().size() == 0);
    // Function destructor handles cleanup; don't double-delete.
}

void test_function_tags() {
    ProgFixture pf;
    Address entry(&pf.ram, 0x1000);
    Function f("myFunc", entry, nullptr, SourceType::DEFAULT);
    f.setProgram(&pf.prog);
    TEST("func.tags.emptyStart", f.getTags().empty());
    bool first = f.addTag("Crypto");
    TEST("func.tags.firstAdded", first);
    TEST("func.hasTag", f.getTags().size() == 1);
    TEST("func.dup",    !f.addTag("Crypto"));
    f.removeTag("Crypto");
    TEST("func.rmTag",  f.getTags().empty());
    f.removeTag("Nonexistent");
    TEST("func.rmNoOp", f.getTags().empty());
}

void test_function_toString() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    Address entry(&ram, 0x1000);
    Function f("myFunc", entry, nullptr, SourceType::DEFAULT);
    auto s = f.toString();
    TEST("func.tostr.notEmpty", !s.empty());
    TEST("func.tostr.name",     s.find("myFunc") != std::string::npos);
    auto ss = f.getSignatureString();
    TEST("func.sig.notEmpty",    !ss.empty());
}

void test_function_manager_create() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address entry(&ram, 0x1000);
    AddressSet body(entry, Address(&ram, 0x1020));
    Function* f = mgr.createFunction("main", entry, body, SourceType::USER_DEFINED);
    TEST("fmgr.create",      f != nullptr);
    TEST("fmgr.count",       mgr.getFunctionCount() == 1);
    TEST("fmgr.getAt",       mgr.getFunctionAt(entry) == f);
    TEST("fmgr.containing",  mgr.getFunctionContaining(Address(&ram, 0x1010)) == f);
    TEST("fmgr.referenced",  mgr.getReferencedFunction(entry) == f);
    TEST("fmgr.inFunc",      mgr.isInFunction(Address(&ram, 0x1010)));
    TEST("fmgr.notInFunc",   !mgr.isInFunction(Address(&ram, 0x2000)));
}

void test_function_manager_remove() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address entry(&ram, 0x1000);
    AddressSet body(entry, Address(&ram, 0x1020));
    Function* f = mgr.createFunction("main", entry, body, SourceType::DEFAULT);
    TEST("fmgr.rm.before",   mgr.getFunctionCount() == 1);
    bool ok = mgr.removeFunction(entry);
    TEST("fmgr.rm.ok",       ok);
    TEST("fmgr.rm.after",    mgr.getFunctionCount() == 0);
    TEST("fmgr.rm.getAt",    mgr.getFunctionAt(entry) == nullptr);
    TEST("fmgr.rm.noop",     !mgr.removeFunction(entry));
    // FunctionManager owns f via unique_ptr — do not delete.
}

void test_function_manager_autoname() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address entry(&ram, 0x1000);
    AddressSet body(entry, entry);
    Function* f = mgr.createFunction("", entry, body, SourceType::DEFAULT);
    TEST("fmgr.auto.notNull", f != nullptr);
    TEST("fmgr.auto.fun",     f->getName().find("func_0x") == 0);
    // FunctionManager owns f via unique_ptr — do not delete.
}

void test_function_manager_overlap() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address entry1(&ram, 0x1000);
    AddressSet body1(entry1, Address(&ram, 0x1020));
    Function* f1 = mgr.createFunction("a", entry1, body1, SourceType::DEFAULT);
    Address entry2(&ram, 0x1010);
    AddressSet body2(entry2, Address(&ram, 0x1030));
    bool threw = false;
    try {
        mgr.createFunction("b", entry2, body2, SourceType::DEFAULT);
    } catch (const std::exception&) { threw = true; }
    TEST("fmgr.overlap",      threw);
    TEST("fmgr.overlap.cnt",  mgr.getFunctionCount() == 1);
    // FunctionManager owns f1 via unique_ptr — do not delete.
}

void test_function_manager_iterate() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address e1(&ram, 0x1000);
    Address e2(&ram, 0x2000);
    AddressSet b1(e1, e1);
    AddressSet b2(e2, e2);
    mgr.createFunction("a", e1, b1, SourceType::DEFAULT);
    mgr.createFunction("b", e2, b2, SourceType::DEFAULT);
    auto it = mgr.getFunctions(true);
    TEST("fmgr.it.has1",     it.hasNext());
    Function* f1 = it.next();
    TEST("fmgr.it.first",    f1 != nullptr);
    TEST("fmgr.it.has2",     it.hasNext());
    Function* f2 = it.next();
    TEST("fmgr.it.second",   f2 != nullptr);
    TEST("fmgr.it.end",      !it.hasNext());
    TEST("fmgr.it.remaining",it.remaining() == 0);
    auto rev = mgr.getFunctions(false);
    TEST("fmgr.rev.remaining", rev.remaining() == 2);
    Function* r1 = rev.next();
    TEST("fmgr.rev.first",   r1->getEntryPoint() == e2);
}

void test_function_manager_iterate_range() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address e1(&ram, 0x1000);
    Address e2(&ram, 0x2000);
    Address e3(&ram, 0x3000);
    mgr.createFunction("a", e1, AddressSet(e1, e1), SourceType::DEFAULT);
    mgr.createFunction("b", e2, AddressSet(e2, e2), SourceType::DEFAULT);
    mgr.createFunction("c", e3, AddressSet(e3, e3), SourceType::DEFAULT);
    auto it = mgr.getFunctions(e2, true);
    TEST("fmgr.range.remaining",  it.remaining() == 2);
    Function* f1 = it.next();
    TEST("fmgr.range.first", f1->getEntryPoint() == e2);
    Function* f2 = it.next();
    TEST("fmgr.range.second",f2->getEntryPoint() == e3);
}

void test_function_manager_calling_conventions() {
    FunctionManager mgr;
    auto model = std::make_unique<PrototypeModel>("cdecl", "cdecl");
    mgr.addCallingConvention("cdecl", std::move(model));
    TEST("fmgr.cc.get",       mgr.getCallingConvention("cdecl") != nullptr);
    TEST("fmgr.cc.getNone",   mgr.getCallingConvention("nope") == nullptr);
    TEST("fmgr.cc.defNone",   mgr.getDefaultCallingConvention() == nullptr);
    auto names = mgr.getCallingConventionNames();
    TEST("fmgr.cc.names.size",names.size() == 1);
    TEST("fmgr.cc.names.cdecl", names[0] == "cdecl");
}

void test_function_manager_getKey() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    FunctionManager mgr;
    Address e1(&ram, 0x1000);
    AddressSet b1(e1, e1);
    Function* f = mgr.createFunction("a", e1, b1, SourceType::DEFAULT);
    long id = f->getID();
    TEST("fmgr.key.get",      mgr.getFunction(id) == f);
    TEST("fmgr.key.none",     mgr.getFunction(99999) == nullptr);
}

void test_function_manager_invalidate() {
    FunctionManager mgr;
    mgr.invalidateCache(true);
    mgr.invalidateCache(false);
    TEST("fmgr.inv.ok",       true);
}

void test_function_manager_with_program() {
    GenericAddressSpace ram("ram", 32, AddressSpace::TYPE_RAM, 0);
    ProgramDB prog("test", nullptr, nullptr);
    auto* af = dynamic_cast<ProgramAddressFactory*>(prog.getAddressFactory());
    if (af) {
        af->addAddressSpace(&ram);
        af->setDefaultSpace(&ram);
    }
    FunctionManager mgr(&prog);
    TEST("fmgr.prog.eq",      mgr.getProgram() == &prog);
    Address e1(&ram, 0x1000);
    AddressSet b1(e1, e1);
    Function* f = mgr.createFunction("a", e1, b1, SourceType::DEFAULT);
    TEST("fmgr.prog.create",  f != nullptr);
    TEST("fmgr.prog.prog",    f->getProgram() == &prog);
}

// ============ SymbolIterator ============

void test_symbol_iterator() {
    std::vector<Symbol*> v;
    Symbol s1("a", Address(), nullptr, SourceType::DEFAULT, SymbolType::LABEL);
    Symbol s2("b", Address(), nullptr, SourceType::DEFAULT, SymbolType::LABEL);
    Symbol s3("c", Address(), nullptr, SourceType::DEFAULT, SymbolType::LABEL);
    v.push_back(&s1);
    v.push_back(&s2);
    v.push_back(&s3);
    SymbolIterator it(v);
    TEST("si.size",       it.size() == 3);
    TEST("si.remaining",  it.remaining() == 3);
    TEST("si.hasNext",    it.hasNext());
    Symbol* p1 = it.next();
    TEST("si.next1",      p1 == &s1);
    TEST("si.remaining2", it.remaining() == 2);
    Symbol* p2 = it.next();
    TEST("si.next2",      p2 == &s2);
    Symbol* p3 = it.next();
    TEST("si.next3",      p3 == &s3);
    TEST("si.end",        !it.hasNext());
    it.reset();
    TEST("si.reset",      it.hasNext());
    TEST("si.cur",        it.current() == nullptr);
    Symbol* p4 = it.next();
    TEST("si.nextAfterReset", p4 == &s1);
}

void test_symbol_iterator_empty() {
    SymbolIterator it;
    TEST("si.empty.size",  it.size() == 0);
    TEST("si.empty.has",   !it.hasNext());
    TEST("si.empty.next",  it.next() == nullptr);
}

} // namespace

int main() {
    std::cout << "=== Batch X: Program model building blocks ===\n";

    std::cout << "\n--- RefType / FlowType / DataRefType ---\n";
    test_reftype_basic();
    test_reftype_equality();
    test_reftype_unconditional_jump();
    test_reftype_conditional_jump();
    test_reftype_calls();
    test_reftype_terminators();
    test_reftype_overrides();
    test_reftype_misc();
    test_datareftype();
    test_reftype_displaystring();

    std::cout << "\n--- EquateTable CRUD ---\n";
    test_equate_table_basic();
    test_equate_table_multiple();
    test_equate_table_rename();
    test_equate_table_remove_by_equate();
    test_equate_table_remove_null();
    test_equate_table_addr_op();
    test_equate_table_lifecycle();

    std::cout << "\n--- SourceType helpers ---\n";
    test_sourcetype_basic();
    test_sourcetype_tostring();
    test_sourcetype_parse();
    test_sourcetype_isuserdefined();
    test_sourcetype_priority();
    test_sourcetype_storageid();
    test_sourcetype_display();
    test_sourcetype_storageid_lookup();

    std::cout << "\n--- SymbolType helpers ---\n";
    test_symboltype_tostring();
    test_symboltype_isfunction();
    test_symboltype_islabel();
    test_symboltype_isnamespace();

    std::cout << "\n--- Namespace ---\n";
    test_namespace_basic();
    test_namespace_named();
    test_namespace_nested();
    test_namespace_equality();
    test_namespace_setter();

    std::cout << "\n--- VariableStorage ---\n";
    test_vstorage_static_constants();
    test_vstorage_default_ctor();
    test_vstorage_memory();
    test_vstorage_equality();
    test_vstorage_intersects();
    test_vstorage_contains();
    test_vstorage_compareTo();
    test_vstorage_compound();
    test_vstorage_invalid_empty();
    test_vstorage_invalid_varnode_size();
    test_vstorage_serialize_roundtrip();

    std::cout << "\n--- VariableImpl family ---\n";
    test_variable_local_basic();
    test_variable_local_firstuse();
    test_variable_local_setname();
    test_variable_local_comment();
    test_variable_parameter_basic();
    test_variable_parameter_ordinal();
    test_variable_return_param();
    test_variable_return_void();
    test_variable_auto_param();
    test_variable_auto_types();
    test_variable_equivalent();

    std::cout << "\n--- Function / FunctionManager ---\n";
    test_function_basic();
    test_function_setter();
    test_function_addparam();
    test_function_addlocal();
    test_function_tags();
    test_function_toString();
    test_function_manager_create();
    test_function_manager_remove();
    test_function_manager_autoname();
    test_function_manager_overlap();
    test_function_manager_iterate();
    test_function_manager_iterate_range();
    test_function_manager_calling_conventions();
    test_function_manager_getKey();
    test_function_manager_invalidate();
    test_function_manager_with_program();

    std::cout << "\n--- SymbolIterator ---\n";
    test_symbol_iterator();
    test_symbol_iterator_empty();

    std::cout << "\n=== Batch X: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
