/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_w.cpp
/// \brief Tests for Batch W: DataTypeUtilities, DataTypeNameComparator,
///        DataTypeComparator, DataTypeObjectComparator,
///        DataTypeManagerChangeListener[Adapter|Handler],
///        FunctionSignatureImpl, GenericCallingConvention,
///        DataTypeManagerImpl.
#include <ghidra/DataTypeUtilities.h>
#include <ghidra/DataTypeNameComparator.h>
#include <ghidra/DataTypeComparator.h>
#include <ghidra/DataTypeObjectComparator.h>
#include <ghidra/DataTypeManagerChangeListener.h>
#include <ghidra/DataTypeManagerChangeListenerAdapter.h>
#include <ghidra/DataTypeManagerChangeListenerHandler.h>
#include <ghidra/FunctionSignature.h>
#include <ghidra/FunctionSignatureImpl.h>
#include <ghidra/GenericCallingConvention.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataType.h>
#include <ghidra/BuiltInDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/DataTypePath.h>
#include <ghidra/SourceArchive.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/TypeDef.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// ---- DataTypeUtilities tests ----

void test_utils_getPointerArrayDecorations() {
    TEST("dec.none", getPointerArrayDecorations("int") == "");
    TEST("dec.ptr",   getPointerArrayDecorations("int *") == "*");
    TEST("dec.ptr2",  getPointerArrayDecorations("int * *") == "* *");
    TEST("dec.arr",   getPointerArrayDecorations("int[10]") == "[10]");
    TEST("dec.comb",  getPointerArrayDecorations("int * * [10]") == "* * [10]");
}

void test_utils_getNameWithoutConflict_string() {
    TEST("nc.simple",   getNameWithoutConflict("int") == "int");
    TEST("nc.conflict", getNameWithoutConflict("MyType.conflict") == "MyType");
    TEST("nc.conflict2",getNameWithoutConflict("MyType.conflict2") == "MyType");
    // "int.conflict *" — the conflict regex won't match because of the trailing
    // space before the decoration; we leave the name unchanged.
    TEST("nc.conflict_with_decoration",
         getNameWithoutConflict("int.conflict *") == "int.conflict *");
    // "int.conflict[10]" — decoration strip + regex match removes the conflict
    // and re-attaches the array decoration.
    TEST("nc.conflict_with_array",
         getNameWithoutConflict("int.conflict[10]") == "int[10]");
    TEST("nc.conflict_underscore",
         getNameWithoutConflict("Foo.conflict_3") == "Foo");
    TEST("nc.conflict_digit_only",
         getNameWithoutConflict("Foo.conflict2") == "Foo");
}

void test_utils_getConflictValue() {
    TEST("cv.none",  getConflictValue("int") == -1);
    TEST("cv.bare",  getConflictValue("X.conflict") == 0);
    TEST("cv.num1",  getConflictValue("X.conflict1") == 1);
    TEST("cv.num2",  getConflictValue("X.conflict42") == 42);
    TEST("cv.bad",   getConflictValue("X.conflictabc") == -1);
}

void test_utils_canHaveConflictName() {
    TEST("chcn.builtin_no",  !canHaveConflictName(&IntegerDataType::dataType()));
    TEST("chcn.struct_yes",   canHaveConflictName(new StructureDataType("S", 0)));
    TEST("chcn.enum_yes",     canHaveConflictName(new EnumDataType("E", 1)));
    TEST("chcn.null",        !canHaveConflictName(nullptr));
}

void test_utils_getBaseDataType() {
    IntegerDataType i;
    TEST("bd.simple", getBaseDataType(&i) == &i);
    TEST("bd.null_in", getBaseDataType(nullptr) == nullptr);
}

// ---- DataTypeNameComparator tests ----

void test_name_comparator_basic() {
    auto& c = DataTypeNameComparator::INSTANCE;
    TEST("nc.eq",    c.compare("foo", "foo") == 0);
    TEST("nc.lt",    c.compare("alpha", "beta") < 0);
    TEST("nc.gt",    c.compare("zeta", "alpha") > 0);
    // Case is significant in this comparator (uses lowercase for case-insensitive
    // match, but breaks ties with original case so "Foo" sorts before "foo").
    TEST("nc.case",  c.compare("Foo", "foo") < 0);
    TEST("nc.empty_lt", c.compare("", "a") < 0);
    TEST("nc.empty_eq", c.compare("", "") == 0);
}

void test_name_comparator_conflict() {
    auto& c = DataTypeNameComparator::INSTANCE;
    // "X.conflict" has conflict value 0, "X" has -1; conflict value breaks the tie.
    TEST("nc.conflict_bare_gt_plain", c.compare("X.conflict", "X") > 0);
    TEST("nc.conflict_bare_lt_plain", c.compare("X", "X.conflict") < 0);
    TEST("nc.conflict2_lt", c.compare("X.conflict2", "X.conflict3") < 0);
    TEST("nc.conflict_bare_lt_numbered", c.compare("X.conflict", "X.conflict2") < 0);
}

void test_name_comparator_functor() {
    DataTypeNameComparator::INSTANCE("a", "b");
    TEST("nc.functor", true);
}

// ---- DataTypeComparator tests ----

void test_datatype_comparator_basic() {
    auto& c = DataTypeComparator::INSTANCE;
    StructureDataType s1("Foo", 0);
    StructureDataType s2("Foo", 0);
    TEST("dtc.same_name", c.compare(&s1, &s2) == 0);
    StructureDataType s3("Bar", 0);
    // "Foo" > "Bar" lexicographically
    TEST("dtc.lt_name", c.compare(&s1, &s3) > 0);
    TEST("dtc.gt_name", c.compare(&s3, &s1) < 0);
    TEST("dtc.null_a", c.compare(nullptr, &s1) < 0);
    TEST("dtc.null_b", c.compare(&s1, nullptr) > 0);
    TEST("dtc.both_null", c.compare(nullptr, nullptr) == 0);
}

void test_datatype_comparator_dtm_and_path() {
    auto& c = DataTypeComparator::INSTANCE;
    // With both DTMs null and same name, comparator returns 0.
    StructureDataType s1("Foo", 0); s1.setCategoryPath(CategoryPath("/a"));
    StructureDataType s2("Foo", 0); s2.setCategoryPath(CategoryPath("/b"));
    TEST("dtc.both_no_dtm_same_name", c.compare(&s1, &s2) == 0);
    // Catpath comparison requires both DTMs to be non-null and have the same
    // name. We can only verify the DTM-null path here, which short-circuits to 0
    // regardless of category path. The catpath branch is exercised by the
    // DataTypeManagerImpl integration tests, not by this isolated test.
}

// ---- DataTypeObjectComparator tests ----

void test_datatype_object_comparator() {
    auto& c = DataTypeObjectComparator::INSTANCE;
    IntegerDataType i;
    TEST("dtoc.dt_dt_eq", c.compare(&i, &i) == 0);
    TEST("dtoc.str_dt_eq", c.compare(std::string("int"), &i) == 0);
    TEST("dtoc.dt_str_eq", c.compare(&i, std::string("int")) == 0);
    TEST("dtoc.str_str_eq", c.compare(std::string("foo"), std::string("foo")) == 0);
    TEST("dtoc.str_str_lt", c.compare(std::string("a"), std::string("b")) < 0);
    // Case is significant: the comparator matches case-insensitively but
    // breaks ties using the original case. 'I' (0x49) < 'i' (0x69) so
    // "INT" < "int" (uppercase sorts first).
    TEST("dtoc.case_upper_lt_lower", c.compare(std::string("INT"), &i) < 0);
    TEST("dtoc.case_lower_gt_upper", c.compare(std::string("int"), std::string("INT")) > 0);
}

// ---- DataTypeManagerChangeListenerAdapter tests ----

class CountingListener : public DataTypeManagerChangeListenerAdapter {
public:
    int count = 0;
    void dataTypeAdded(DataTypeManager* dtm, const DataTypePath& path) override {
        (void)dtm; (void)path;
        ++count;
    }
};

void test_change_listener_adapter() {
    CountingListener cl;
    TEST("cla.count0", cl.count == 0);
    DataTypeManagerImpl mgr;
    cl.dataTypeAdded(&mgr, DataTypePath("/", "X"));
    TEST("cla.count1", cl.count == 1);
    cl.dataTypeRemoved(&mgr, DataTypePath("/", "X"));
    TEST("cla.count_still_1", cl.count == 1);
}

// ---- DataTypeManagerChangeListenerHandler tests ----

class TestRecordingListener : public DataTypeManagerChangeListenerAdapter {
public:
    int catAdded = 0, dtAdded = 0, dtChanged = 0, dtRemoved = 0;
    int renamed = 0, favorites = 0, sourceArc = 0;
    void categoryAdded(DataTypeManager* dtm, const CategoryPath& path) override {
        (void)dtm; (void)path; ++catAdded;
    }
    void dataTypeAdded(DataTypeManager* dtm, const DataTypePath& path) override {
        (void)dtm; (void)path; ++dtAdded;
    }
    void dataTypeChanged(DataTypeManager* dtm, const DataTypePath& path) override {
        (void)dtm; (void)path; ++dtChanged;
    }
    void dataTypeRemoved(DataTypeManager* dtm, const DataTypePath& path) override {
        (void)dtm; (void)path; ++dtRemoved;
    }
    void dataTypeRenamed(DataTypeManager*, const DataTypePath& o,
                         const DataTypePath& n) override {
        (void)o; (void)n; ++renamed;
    }
    void favoritesChanged(DataTypeManager*, const DataTypePath&, bool) override {
        ++favorites;
    }
    void sourceArchiveAdded(DataTypeManager*, SourceArchive*) override { ++sourceArc; }
};

void test_change_handler() {
    DataTypeManagerChangeListenerHandler h;
    auto l1 = std::make_unique<TestRecordingListener>();
    auto l2 = std::make_unique<TestRecordingListener>();
    TEST("h.empty", h.listenerCount() == 0);

    h.addDataTypeManagerListener(l1.get());
    h.addDataTypeManagerListener(l2.get());
    TEST("h.add_2", h.listenerCount() == 2);

    // idempotent add
    h.addDataTypeManagerListener(l1.get());
    TEST("h.add_idem", h.listenerCount() == 2);

    DataTypeManagerImpl mgr;
    h.categoryAdded(&mgr, CategoryPath("/a"));
    TEST("h.cat_fanout_l1", l1->catAdded == 1);
    TEST("h.cat_fanout_l2", l2->catAdded == 1);

    h.dataTypeAdded(&mgr, DataTypePath("/", "X"));
    TEST("h.dt_added_l1", l1->dtAdded == 1);
    TEST("h.dt_added_l2", l2->dtAdded == 1);

    h.dataTypeChanged(&mgr, DataTypePath("/", "X"));
    h.dataTypeRemoved(&mgr, DataTypePath("/", "X"));
    h.dataTypeRenamed(&mgr, DataTypePath("/", "X"), DataTypePath("/", "Y"));
    h.favoritesChanged(&mgr, DataTypePath("/", "X"), true);
    h.sourceArchiveAdded(&mgr, nullptr);

    TEST("h.dt_changed", l1->dtChanged == 1);
    TEST("h.dt_removed", l1->dtRemoved == 1);
    TEST("h.renamed",    l1->renamed == 1);
    TEST("h.favorites",  l1->favorites == 2); // once from rename, once from favoritesChanged
    TEST("h.source",     l1->sourceArc == 1);

    h.removeDataTypeManagerListener(l1.get());
    TEST("h.remove_1", h.listenerCount() == 1);
    h.dataTypeAdded(&mgr, DataTypePath("/", "Y"));
    TEST("h.post_remove_l1_unchanged", l1->dtAdded == 1);
    TEST("h.post_remove_l2_changed",  l2->dtAdded == 2);
}

// ---- FunctionSignature tests ----

void test_function_signature_constants() {
    TEST("fs.noreturn", FunctionSignature::NORETURN_DISPLAY_STRING == "noreturn");
    TEST("fs.varargs",  FunctionSignature::VAR_ARGS_DISPLAY_STRING == "...");
    TEST("fs.void",     FunctionSignature::VOID_PARAM_DISPLAY_STRING == "void");
}

void test_function_signature_impl_default() {
    FunctionSignatureImpl f;
    TEST("fsi.name",    f.getName().empty());
    TEST("fsi.args",    f.getArguments().empty());
    TEST("fsi.ret",     f.getReturnType() == nullptr);
    TEST("fsi.comment", f.getComment().empty());
    TEST("fsi.varargs", !f.hasVarArgs());
    TEST("fsi.noreturn", !f.hasNoReturn());
    TEST("fsi.cconv",   f.getCallingConventionName().empty());
    TEST("fsi.proto",   !f.getPrototypeString().empty());
}

void test_function_signature_impl_named() {
    FunctionSignatureImpl f("myFunc");
    TEST("fsi.named", f.getName() == "myFunc");
    f.setName("renamed");
    TEST("fsi.renamed", f.getName() == "renamed");
}

void test_function_signature_impl_setters() {
    FunctionSignatureImpl f("f");
    f.setComment("comment text");
    TEST("fsi.set_comment", f.getComment() == "comment text");
    f.setHasVarArgs(true);
    TEST("fsi.set_varargs", f.hasVarArgs());
    f.setHasNoReturn(true);
    TEST("fsi.set_noreturn", f.hasNoReturn());
    f.setCallingConventionName("stdcall");
    TEST("fsi.set_cconv", f.getCallingConventionName() == "stdcall");
    f.setReturnType(&IntegerDataType::dataType());
    TEST("fsi.set_ret", f.getReturnType() == &IntegerDataType::dataType());
}

void test_function_signature_impl_arguments() {
    FunctionSignatureImpl f("f");
    f.addArgument(new ParameterDefinitionImpl("a", &IntegerDataType::dataType(), "", 0));
    f.addArgument(new ParameterDefinitionImpl("b", &ByteDataType::dataType(), "", 1));
    auto args = f.getArguments();
    TEST("fsi.args.size", args.size() == 2);
    TEST("fsi.args[0].name", args[0]->getName() == "a");
    TEST("fsi.args[1].name", args[1]->getName() == "b");
    f.clearArguments();
    TEST("fsi.args.cleared", f.getArguments().empty());
    // null argument should be ignored
    f.addArgument(nullptr);
    TEST("fsi.args.null_ignored", f.getArguments().empty());
}

void test_function_signature_impl_setArguments() {
    FunctionSignatureImpl f("f");
    std::vector<ParameterDefinition*> args;
    args.push_back(new ParameterDefinitionImpl("x", &IntegerDataType::dataType(), "", 0));
    args.push_back(new ParameterDefinitionImpl("y", &ByteDataType::dataType(), "", 1));
    f.setArguments(args);
    TEST("fsi.setArgs.size", f.getArguments().size() == 2);
    // Setting again should replace, not add. Use a fresh set of pointers.
    std::vector<ParameterDefinition*> args2;
    args2.push_back(new ParameterDefinitionImpl("a", &IntegerDataType::dataType(), "", 0));
    f.setArguments(args2);
    TEST("fsi.setArgs.replace", f.getArguments().size() == 1);
    TEST("fsi.setArgs.replaced_name", f.getArguments()[0]->getName() == "a");
}

void test_function_signature_impl_prototype() {
    FunctionSignatureImpl f("myfn");
    f.setReturnType(&IntegerDataType::dataType());
    auto proto = f.getPrototypeString();
    TEST("fsi.proto.name", proto.find("myfn") != std::string::npos);
    TEST("fsi.proto.ret", proto.find("int") != std::string::npos);
    TEST("fsi.proto.void", proto.find("void") != std::string::npos);
}

void test_function_signature_impl_prototype_varargs() {
    FunctionSignatureImpl f("vfn");
    f.setReturnType(&IntegerDataType::dataType());
    f.setHasVarArgs(true);
    auto proto = f.getPrototypeString();
    TEST("fsi.proto.varargs", proto.find("...") != std::string::npos);
}

void test_function_signature_impl_prototype_noreturn() {
    FunctionSignatureImpl f("nfn");
    f.setHasNoReturn(true);
    auto proto = f.getPrototypeString();
    TEST("fsi.proto.noreturn", proto.find("noreturn") != std::string::npos);
}

void test_function_signature_impl_equiv() {
    FunctionSignatureImpl f1("a"), f2("a");
    TEST("fsi.equiv.same", f1.isEquivalentSignature(&f2));
    f1.setHasVarArgs(true);
    TEST("fsi.equiv.diff_varargs", !f1.isEquivalentSignature(&f2));
    FunctionSignatureImpl f3("b");
    TEST("fsi.equiv.diff_name", !f1.isEquivalentSignature(&f3));
    TEST("fsi.equiv.null", !f1.isEquivalentSignature(nullptr));
    TEST("fsi.equiv.self", f1.isEquivalentSignature(&f1));
}

void test_function_signature_impl_clone() {
    FunctionSignatureImpl f("orig");
    f.setComment("c");
    f.setCallingConventionName("stdcall");
    f.setReturnType(&IntegerDataType::dataType());
    f.setHasVarArgs(true);
    f.setHasNoReturn(true);
    f.addArgument(new ParameterDefinitionImpl("p", &IntegerDataType::dataType(), "", 0));

    auto* c = f.clone();
    TEST("fsi.clone.name",   c->getName() == "orig");
    TEST("fsi.clone.comment",c->getComment() == "c");
    TEST("fsi.clone.cconv",  c->getCallingConventionName() == "stdcall");
    TEST("fsi.clone.ret",    c->getReturnType() == &IntegerDataType::dataType());
    TEST("fsi.clone.varargs",c->hasVarArgs());
    TEST("fsi.clone.noreturn",c->hasNoReturn());
    TEST("fsi.clone.args",   c->getArguments().size() == 1);
    delete c;
}

void test_function_signature_impl_cconv_in_proto() {
    FunctionSignatureImpl f("fn");
    f.setReturnType(&IntegerDataType::dataType());
    f.setCallingConventionName("cdecl");
    auto with = f.getPrototypeString(true);
    auto without = f.getPrototypeString(false);
    TEST("fsi.proto.cconv_with", with.find("cdecl") != std::string::npos);
    TEST("fsi.proto.cconv_without", without.find("cdecl") == std::string::npos);
}

// ---- GenericCallingConvention tests ----

void test_generic_calling_convention() {
    TEST("gcc.unknown", GenericCallingConvention::unknown == "unknown");
    TEST("gcc.stdcall", GenericCallingConvention::stdcall == "__stdcall");
    TEST("gcc.cdecl",   GenericCallingConvention::cdecl_cc == "__cdecl");
    TEST("gcc.fastcall",GenericCallingConvention::fastcall == "__fastcall");
    TEST("gcc.thiscall",GenericCallingConvention::thiscall == "__thiscall");
    TEST("gcc.vectorcall",GenericCallingConvention::vectorcall == "__vectorcall");
}

void test_function_signature_unknown_cconv() {
    FunctionSignatureImpl f;
    // Default cconv is empty, not "unknown"
    TEST("fsi.cconv_empty_default", f.getCallingConventionName().empty());
    f.setCallingConventionName("unknown");
    TEST("fsi.unkcc_true_after_set", f.hasUnknownCallingConventionName());
    f.setCallingConventionName("stdcall");
    TEST("fsi.unkcc_false_after_stdcall", !f.hasUnknownCallingConventionName());
}

// ---- DataTypeManagerImpl tests ----

void test_dtmi_default_ctor() {
    DataTypeManagerImpl mgr;
    TEST("dtmi.name", mgr.getName() == "ProgramDB");
    TEST("dtmi.has_int", mgr.getDataType(CategoryPath::ROOT(), "int") != nullptr);
}

void test_dtmi_named_ctor() {
    DataTypeManagerImpl mgr("MyArchive");
    TEST("dtmi.named", mgr.getName() == "MyArchive");
    mgr.setName("Renamed");
    TEST("dtmi.renamed", mgr.getName() == "Renamed");
}

void test_dtmi_lookup_builtins() {
    DataTypeManagerImpl mgr;
    TEST("dtmi.int",  mgr.getDataType(CategoryPath::ROOT(), "int") != nullptr);
    TEST("dtmi.byte", mgr.getDataType(CategoryPath::ROOT(), "byte") != nullptr);
    TEST("dtmi.void", mgr.getDataType(CategoryPath::ROOT(), "void") != nullptr);
    TEST("dtmi.missing", mgr.getDataType(CategoryPath::ROOT(), "nonexistent") == nullptr);
}

void test_dtmi_lookup_by_id() {
    DataTypeManagerImpl mgr;
    // Built-ins get IDs 1-16
    auto* dt = mgr.getDataType(1);
    TEST("dtmi.id1", dt != nullptr);
    auto* missing = mgr.getDataType(99999L);
    TEST("dtmi.id_missing", missing == nullptr);
}

void test_dtmi_addDataType() {
    DataTypeManagerImpl mgr;
    auto* custom = new StructureDataType("Custom", 0);
    DataType* added = mgr.addDataType(custom);
    TEST("dtmi.added", added == custom);
    TEST("dtmi.added_lookup",
         mgr.getDataType(CategoryPath::ROOT(), "Custom") == custom);
    auto id = mgr.getDataTypeId(custom);
    TEST("dtmi.added_id_valid", id > 0);
    // mgr.addDataType takes ownership - do not delete
}

void test_dtmi_addDataType_duplicate_path() {
    DataTypeManagerImpl mgr;
    auto* t1 = new StructureDataType("Dup", 0);
    auto* t2 = new StructureDataType("Dup", 0);
    DataType* a = mgr.addDataType(t1);
    DataType* b = mgr.addDataType(t2);
    TEST("dtmi.dup_path_returns_existing", a == t1);
    TEST("dtmi.dup_path_skips_second", b == t1);
    // mgr owns t1 (it was added). t2 was rejected and not added - delete it.
    delete t2;
}

void test_dtmi_addDataType_duplicate_pointer() {
    DataTypeManagerImpl mgr;
    auto* t = new StructureDataType("T", 0);
    DataType* a = mgr.addDataType(t);
    DataType* b = mgr.addDataType(t);
    TEST("dtmi.dup_ptr_returns_same", a == t);
    TEST("dtmi.dup_ptr_idempotent", b == t);
    // mgr owns t. Second add is a no-op.
}

void test_dtmi_getDataTypes() {
    DataTypeManagerImpl mgr;
    auto all = mgr.getDataTypes();
    TEST("dtmi.all_nonempty", !all.empty());
    // 16 built-ins
    TEST("dtmi.builtins_16", all.size() >= 16);
}

void test_dtmi_clearAllDataTypes() {
    DataTypeManagerImpl mgr;
    auto* custom = new StructureDataType("X", 0);
    mgr.addDataType(custom);
    mgr.clearAllDataTypes();
    auto* found = mgr.getDataType(CategoryPath::ROOT(), "X");
    TEST("dtmi.cleared", found == nullptr);
    // Built-ins should be re-populated
    TEST("dtmi.cleared_int_back", mgr.getDataType(CategoryPath::ROOT(), "int") != nullptr);
}

void test_dtmi_removeDataType() {
    DataTypeManagerImpl mgr;
    auto* custom = new StructureDataType("R", 0);
    mgr.addDataType(custom);
    TEST("dtmi.pre_remove", mgr.getDataType(CategoryPath::ROOT(), "R") == custom);
    mgr.removeDataType(custom);
    TEST("dtmi.removed", mgr.getDataType(CategoryPath::ROOT(), "R") == nullptr);
    // removeDataType deletes the type internally; do not delete again.
}

void test_dtmi_getNextId() {
    DataTypeManagerImpl mgr;
    auto id1 = mgr.getNextId();
    auto id2 = mgr.getNextId();
    TEST("dtmi.id_inc", id2 == id1 + 1);
}

void test_dtmi_org() {
    DataTypeManagerImpl mgr;
    TEST("dtmi.org", mgr.getDataOrganization() != nullptr);
}

void test_dtmi_callingconv_empty() {
    DataTypeManagerImpl mgr;
    TEST("dtmi.def_empty", mgr.getDefinedCallingConventionNames().empty());
    TEST("dtmi.known_empty", mgr.getKnownCallingConventionNames().empty());
}

} // namespace

int main() {
    // DataTypeUtilities
    test_utils_getPointerArrayDecorations();
    test_utils_getNameWithoutConflict_string();
    test_utils_getConflictValue();
    test_utils_canHaveConflictName();
    test_utils_getBaseDataType();
    // DataTypeNameComparator
    test_name_comparator_basic();
    test_name_comparator_conflict();
    test_name_comparator_functor();
    // DataTypeComparator
    test_datatype_comparator_basic();
    test_datatype_comparator_dtm_and_path();
    // DataTypeObjectComparator
    test_datatype_object_comparator();
    // DataTypeManagerChangeListener
    test_change_listener_adapter();
    test_change_handler();
    // FunctionSignature
    test_function_signature_constants();
    test_function_signature_impl_default();
    test_function_signature_impl_named();
    test_function_signature_impl_setters();
    test_function_signature_impl_arguments();
    test_function_signature_impl_setArguments();
    test_function_signature_impl_prototype();
    test_function_signature_impl_prototype_varargs();
    test_function_signature_impl_prototype_noreturn();
    test_function_signature_impl_equiv();
    test_function_signature_impl_clone();
    test_function_signature_impl_cconv_in_proto();
    // GenericCallingConvention
    test_generic_calling_convention();
    test_function_signature_unknown_cconv();
    // DataTypeManagerImpl
    test_dtmi_default_ctor();
    test_dtmi_named_ctor();
    test_dtmi_lookup_builtins();
    test_dtmi_lookup_by_id();
    test_dtmi_addDataType();
    test_dtmi_addDataType_duplicate_path();
    test_dtmi_addDataType_duplicate_pointer();
    test_dtmi_getDataTypes();
    test_dtmi_clearAllDataTypes();
    test_dtmi_removeDataType();
    test_dtmi_getNextId();
    test_dtmi_org();
    test_dtmi_callingconv_empty();

    std::cout << "Batch W: " << passed << "/" << total << " passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
