/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_u.cpp
/// \brief Tests for Batch U: SourceArchiveImpl, DataTypeConflictHandler,
///        DataTypePath, ParameterDefinition/Impl, FunctionDefinition,
///        FunctionDefinitionDataType, ArrayDataType, DataTypeImpl.
#include <ghidra/SourceArchiveImpl.h>
#include <ghidra/SourceArchive.h>
#include <ghidra/UniversalID.h>
#include <ghidra/ArchiveType.h>
#include <ghidra/DataTypeConflictHandler.h>
#include <ghidra/DataTypePath.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/ParameterDefinition.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/Array.h>
#include <ghidra/DataTypeImpl.h>
#include <ghidra/DataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/AbstractDataType.h>
#include <ghidra/StandAloneDataTypeManager.h>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <typeinfo>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

// ---- UniversalID tests ----

void test_universal_id() {
    UniversalID a(42);
    UniversalID b(42);
    UniversalID c(99);
    TEST("uid.eq", a == b);
    TEST("uid.neq", a != c);
    TEST("uid.lt", a < c);
    TEST("uid.gt", c > a);
    TEST("uid.value", a.getValue() == 42);
    TEST("uid.toString", a.toString() == "42");
}

// ---- ArchiveTypeUtil tests ----

void test_archive_type_util() {
    TEST("archive.builtin.yes", ArchiveTypeUtil::isBuiltIn(ArchiveType::BUILT_IN));
    TEST("archive.builtin.no", !ArchiveTypeUtil::isBuiltIn(ArchiveType::FILE));
    TEST("archive.valid.file", ArchiveTypeUtil::isValidSourceArchive(ArchiveType::FILE));
    TEST("archive.valid.project", ArchiveTypeUtil::isValidSourceArchive(ArchiveType::PROJECT));
    TEST("archive.valid.builtin.no", !ArchiveTypeUtil::isValidSourceArchive(ArchiveType::BUILT_IN));
    TEST("archive.valid.program.no", !ArchiveTypeUtil::isValidSourceArchive(ArchiveType::PROGRAM));
}

// ---- SourceArchiveImpl tests ----

void test_source_archive_2arg() {
    SourceArchiveImpl a(UniversalID(1), ArchiveType::FILE, "MyArchive");
    TEST("sa2.id", a.getSourceArchiveID() == UniversalID(1));
    TEST("sa2.type", a.getArchiveType() == ArchiveType::FILE);
    TEST("sa2.name", a.getName() == "MyArchive");
    TEST("sa2.fileID.empty", a.getDomainFileID() == "");
    TEST("sa2.syncTime", a.getLastSyncTime() == 0);
    TEST("sa2.clean", !a.isDirty());
}

void test_source_archive_4arg() {
    SourceArchiveImpl a(UniversalID(7), "DOM-123", ArchiveType::PROJECT, "Proj");
    TEST("sa4.id", a.getSourceArchiveID() == UniversalID(7));
    TEST("sa4.fileID", a.getDomainFileID() == "DOM-123");
    TEST("sa4.type", a.getArchiveType() == ArchiveType::PROJECT);
    TEST("sa4.name", a.getName() == "Proj");
    TEST("sa4.syncTime", a.getLastSyncTime() == 0);
    TEST("sa4.clean", !a.isDirty());
}

void test_source_archive_6arg() {
    SourceArchiveImpl a(UniversalID(99), "FILE-7", ArchiveType::PROGRAM, "Prog",
                        1700000000LL, true);
    TEST("sa6.id", a.getSourceArchiveID() == UniversalID(99));
    TEST("sa6.fileID", a.getDomainFileID() == "FILE-7");
    TEST("sa6.type", a.getArchiveType() == ArchiveType::PROGRAM);
    TEST("sa6.name", a.getName() == "Prog");
    TEST("sa6.syncTime", a.getLastSyncTime() == 1700000000LL);
    TEST("sa6.dirty", a.isDirty());
}

void test_source_archive_setters() {
    SourceArchiveImpl a(UniversalID(5), ArchiveType::FILE, "Old");
    a.setLastSyncTime(1234567890LL);
    TEST("sa.set.sync", a.getLastSyncTime() == 1234567890LL);
    a.setName("New");
    TEST("sa.set.name", a.getName() == "New");
    a.setDirtyFlag(false);
    TEST("sa.set.clean", !a.isDirty());
    a.setDirtyFlag(true);
    TEST("sa.set.dirty", a.isDirty());
}

// ---- DataTypeConflictHandler tests ----

void test_conflict_handler_default() {
    DataTypeConflictHandler& h = DataTypeConflictHandler::DEFAULT_HANDLER();
    ByteDataType a; ByteDataType b;
    auto res = h.resolveConflict(&a, &b);
    TEST("ch.default.resolve", res == DataTypeConflictHandler::ConflictResult::RENAME_AND_ADD);
    TEST("ch.default.update", h.shouldUpdate(&a, &b));
    TEST("ch.default.subsequent", h.getSubsequentHandler() != nullptr);
    auto* sub = h.getSubsequentHandler();
    TEST("ch.default.sub.resolve",
         sub->resolveConflict(&a, &b) == DataTypeConflictHandler::ConflictResult::RENAME_AND_ADD);
    TEST("ch.default.sub.update", !sub->shouldUpdate(&a, &b));
}

void test_conflict_handler_keep() {
    DataTypeConflictHandler& h = DataTypeConflictHandler::KEEP_HANDLER();
    ByteDataType a; ByteDataType b;
    auto res = h.resolveConflict(&a, &b);
    TEST("ch.keep.resolve", res == DataTypeConflictHandler::ConflictResult::USE_EXISTING);
    TEST("ch.keep.update", !h.shouldUpdate(&a, &b));
    TEST("ch.keep.subsequent.self", h.getSubsequentHandler() == &h);
}

void test_conflict_handler_replace() {
    DataTypeConflictHandler& h = DataTypeConflictHandler::REPLACE_HANDLER();
    ByteDataType a; ByteDataType b;
    auto res = h.resolveConflict(&a, &b);
    TEST("ch.replace.resolve", res == DataTypeConflictHandler::ConflictResult::REPLACE_EXISTING);
    TEST("ch.replace.update", h.shouldUpdate(&a, &b));
    auto* sub = h.getSubsequentHandler();
    TEST("ch.replace.sub.resolve",
         sub->resolveConflict(&a, &b) == DataTypeConflictHandler::ConflictResult::REPLACE_EXISTING);
    TEST("ch.replace.sub.update", !sub->shouldUpdate(&a, &b));
}

void test_conflict_handler_empty_struct() {
    DataTypeConflictHandler& h = DataTypeConflictHandler::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER();
    StandAloneDataTypeManager mgr("test_handler_esa");
    StructureDataType s1("Empty", 0);
    StructureDataType s2("Empty", 0);
    s2.add(&IntegerDataType::dataType());
    TEST("ch.esa.addedEmpty",
         h.resolveConflict(&s1, &s2) == DataTypeConflictHandler::ConflictResult::USE_EXISTING);
    TEST("ch.esa.existingEmpty",
         h.resolveConflict(&s2, &s1) == DataTypeConflictHandler::ConflictResult::REPLACE_EXISTING);
    TEST("ch.esa.bothDefined",
         h.resolveConflict(&s2, &s2) == DataTypeConflictHandler::ConflictResult::RENAME_AND_ADD);
    ByteDataType a; ByteDataType b;
    TEST("ch.esa.nonStruct",
         h.resolveConflict(&a, &b) == DataTypeConflictHandler::ConflictResult::RENAME_AND_ADD);
    TEST("ch.esa.update", !h.shouldUpdate(&a, &b));
    TEST("ch.esa.subsequent.self", h.getSubsequentHandler() == &h);
}

void test_conflict_handler_empty_union() {
    DataTypeConflictHandler& h = DataTypeConflictHandler::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER();
    UnionDataType u1("EmptyU", 0);
    UnionDataType u2("EmptyU", 0);
    u2.add(&IntegerDataType::dataType());
    TEST("ch.eua.addedEmpty",
         h.resolveConflict(&u1, &u2) == DataTypeConflictHandler::ConflictResult::USE_EXISTING);
    TEST("ch.eua.existingEmpty",
         h.resolveConflict(&u2, &u1) == DataTypeConflictHandler::ConflictResult::REPLACE_EXISTING);
}

void test_conflict_handler_builtin_throws() {
    DataTypeConflictHandler& h = DataTypeConflictHandler::BUILT_IN_MANAGER_HANDLER();
    ByteDataType a; ByteDataType b;
    bool threw = false;
    try { h.resolveConflict(&a, &b); }
    catch (const std::exception&) { threw = true; }
    TEST("ch.builtin.throws", threw);
    TEST("ch.builtin.update", !h.shouldUpdate(&a, &b));
}

void test_conflict_handler_getHandler() {
    auto* h1 = DataTypeConflictHandler::getHandler(DataTypeConflictHandler::ConflictResolutionPolicy::RENAME_AND_ADD);
    auto* h2 = DataTypeConflictHandler::getHandler(DataTypeConflictHandler::ConflictResolutionPolicy::USE_EXISTING);
    auto* h3 = DataTypeConflictHandler::getHandler(DataTypeConflictHandler::ConflictResolutionPolicy::REPLACE_EXISTING);
    auto* h4 = DataTypeConflictHandler::getHandler(DataTypeConflictHandler::ConflictResolutionPolicy::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD);
    auto* h5 = DataTypeConflictHandler::getHandler(static_cast<DataTypeConflictHandler::ConflictResolutionPolicy>(99));
    TEST("ch.get.rename", h1 == &DataTypeConflictHandler::DEFAULT_HANDLER());
    TEST("ch.get.keep", h2 == &DataTypeConflictHandler::KEEP_HANDLER());
    TEST("ch.get.replace", h3 == &DataTypeConflictHandler::REPLACE_HANDLER());
    TEST("ch.get.empty", h4 == &DataTypeConflictHandler::REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER());
    TEST("ch.get.fallback", h5 == &DataTypeConflictHandler::DEFAULT_HANDLER());
}

// ---- DataTypePath tests ----

void test_datatype_path_string_ctor() {
    DataTypePath p("/cat1/cat2", "MyType");
    TEST("path.catPath", p.getCategoryPath() == CategoryPath("/cat1/cat2"));
    TEST("path.name", p.getDataTypeName() == "MyType");
    TEST("path.full", p.getPath() == "/cat1/cat2/MyType");
    TEST("path.toString", p.toString() == "/cat1/cat2/MyType");
}

void test_datatype_path_category_ctor() {
    CategoryPath cat("/a/b");
    DataTypePath p(cat, "Name");
    TEST("path2.catPath", p.getCategoryPath() == cat);
    TEST("path2.name", p.getDataTypeName() == "Name");
    TEST("path2.full", p.getPath() == "/a/b/Name");
}

void test_datatype_path_eq() {
    DataTypePath a("/a/b", "T");
    DataTypePath b("/a/b", "T");
    DataTypePath c("/a/b", "U");
    DataTypePath d("/a/c", "T");
    TEST("path.eq.yes", a == b);
    TEST("path.eq.no.name", !(a == c));
    TEST("path.eq.no.cat", !(a == d));
    TEST("path.neq", a != c);
    TEST("path.neq.same", !(a != b));
}

void test_datatype_path_compare() {
    DataTypePath a("/a", "A");
    DataTypePath b("/b", "A");
    DataTypePath c("/a", "B");
    TEST("path.lt.cat", a.compareTo(b) < 0);
    TEST("path.lt.name", a.compareTo(c) < 0);
    TEST("path.op.lt", a < b);
    TEST("path.op.gt", b > a);
    TEST("path.op.lt.self", !(a < a));
    TEST("path.op.gt.self", !(a > a));
}

void test_datatype_path_isAncestor() {
    DataTypePath p("/a/b/c", "T");
    TEST("path.ancestor.self", p.isAncestor(p.getCategoryPath()));
    TEST("path.ancestor.parent", p.isAncestor(CategoryPath("/a/b")));
    TEST("path.ancestor.root", p.isAncestor(CategoryPath("/a")));
    TEST("path.ancestor.sibling", !p.isAncestor(CategoryPath("/a/b/d")));
    TEST("path.ancestor.different", !p.isAncestor(CategoryPath("/x")));
}

void test_datatype_path_hash() {
    DataTypePath a("/a/b", "T");
    DataTypePath b("/a/b", "T");
    std::hash<DataTypePath> h;
    TEST("path.hash.eq", h(a) == h(b));
}

// ---- ParameterDefinitionImpl tests ----

void test_param_def_basic() {
    ParameterDefinitionImpl p("p1", &IntegerDataType::dataType(), "a param", 0);
    TEST("parm.name", p.getName() == "p1");
    TEST("parm.dt", p.getDataType() == &IntegerDataType::dataType());
    TEST("parm.comment", p.getComment() == "a param");
    TEST("parm.ordinal", p.getOrdinal() == 0);
    TEST("parm.length", p.getLength() == IntegerDataType::dataType().getLength());
    TEST("parm.ownsDT", !p.ownsDataType());
}

void test_param_def_setters() {
    ParameterDefinitionImpl p("old", &ByteDataType::dataType(), "", 0);
    p.setName("newName");
    p.setComment("new comment");
    p.setDataType(&IntegerDataType::dataType());
    TEST("parm.set.name", p.getName() == "newName");
    TEST("parm.set.comment", p.getComment() == "new comment");
    TEST("parm.set.dt", p.getDataType() == &IntegerDataType::dataType());
}

void test_param_def_equivalent() {
    ParameterDefinitionImpl p1("p", &IntegerDataType::dataType(), "c", 0);
    ParameterDefinitionImpl p2("p", &IntegerDataType::dataType(), "c", 0);
    ParameterDefinitionImpl p3("p", &ByteDataType::dataType(), "c", 0);
    ParameterDefinitionImpl p4("q", &IntegerDataType::dataType(), "c", 0);
    ParameterDefinitionImpl p5("p", &IntegerDataType::dataType(), "d", 0);
    TEST("parm.eq.same", p1.isEquivalent(&p2));
    TEST("parm.eq.dt", !p1.isEquivalent(&p3));
    TEST("parm.eq.name", !p1.isEquivalent(&p4));
    TEST("parm.eq.comment", !p1.isEquivalent(&p5));
}

void test_param_def_toString() {
    ParameterDefinitionImpl p("p1", &IntegerDataType::dataType(), "", 0);
    auto s = p.toString();
    TEST("parm.toString.contains_name", s.find("p1") != std::string::npos);
}

// ---- FunctionDefinitionDataType tests ----

void test_funcdef_default() {
    FunctionDefinitionDataType f("MyFn");
    TEST("fd.default.name", f.getName() == "MyFn");
    TEST("fd.default.args", f.getArguments().empty());
    TEST("fd.default.returnType", f.getReturnType() == nullptr);
    TEST("fd.default.comment", f.getComment() == "");
    TEST("fd.default.noVarargs", !f.hasVarArgs());
    TEST("fd.default.noNoreturn", !f.hasNoReturn());
    TEST("fd.default.cconv", f.getCallingConventionName() == "unknown");
    TEST("fd.default.length", f.getLength() == -1);
}

void test_funcdef_set_return_type() {
    FunctionDefinitionDataType f("Fn");
    f.setReturnType(&IntegerDataType::dataType());
    TEST("fd.ret.eq", f.getReturnType() == &IntegerDataType::dataType());
    TEST("fd.ret.display", f.getReturnType()->getDisplayName() == "int");
}

void test_funcdef_set_comment() {
    FunctionDefinitionDataType f("Fn");
    f.setComment("a function");
    TEST("fd.comment", f.getComment() == "a function");
}

void test_funcdef_set_var_args() {
    FunctionDefinitionDataType f("Fn");
    f.setVarArgs(true);
    TEST("fd.varargs", f.hasVarArgs());
    f.setVarArgs(false);
    TEST("fd.varargs.false", !f.hasVarArgs());
}

void test_funcdef_set_noreturn() {
    FunctionDefinitionDataType f("Fn");
    f.setNoReturn(true);
    TEST("fd.noreturn", f.hasNoReturn());
}

void test_funcdef_set_cconv() {
    FunctionDefinitionDataType f("Fn");
    f.setCallingConvention("stdcall");
    TEST("fd.cconv", f.getCallingConventionName() == "stdcall");
}

void test_funcdef_set_arguments() {
    FunctionDefinitionDataType f("Fn");
    std::vector<ParameterDefinition*> args;
    args.push_back(new ParameterDefinitionImpl("a", &IntegerDataType::dataType(), "", 0, false));
    args.push_back(new ParameterDefinitionImpl("b", &ByteDataType::dataType(), "", 1, false));
    f.setArguments(args);
    auto got = f.getArguments();
    TEST("fd.args.size", got.size() == 2);
    TEST("fd.args[0].name", got[0]->getName() == "a");
    TEST("fd.args[1].name", got[1]->getName() == "b");
    TEST("fd.args[0].ord", got[0]->getOrdinal() == 0);
    TEST("fd.args[1].ord", got[1]->getOrdinal() == 1);
    for (auto* p : args) delete p;
}

void test_funcdef_prototype_string() {
    FunctionDefinitionDataType f("fn");
    f.setReturnType(&IntegerDataType::dataType());
    std::vector<ParameterDefinition*> args;
    args.push_back(new ParameterDefinitionImpl("x", &IntegerDataType::dataType(), "", 0, false));
    f.setArguments(args);
    auto proto = f.getPrototypeString();
    TEST("fd.proto.contains.ret", proto.find("int") != std::string::npos);
    TEST("fd.proto.contains.name", proto.find("fn") != std::string::npos);
    TEST("fd.proto.contains.x", proto.find("x") != std::string::npos);
    TEST("fd.proto.void", f.getPrototypeString().find("void") == std::string::npos);
    for (auto* p : args) delete p;
}

void test_funcdef_prototype_void() {
    FunctionDefinitionDataType f("fn");
    f.setReturnType(&IntegerDataType::dataType());
    auto proto = f.getPrototypeString();
    TEST("fd.proto.voidyes", proto.find("void") != std::string::npos);
}

void test_funcdef_prototype_varargs() {
    FunctionDefinitionDataType f("fn");
    f.setVarArgs(true);
    auto proto = f.getPrototypeString();
    TEST("fd.proto.varargs", proto.find("...") != std::string::npos);
}

void test_funcdef_clone_same_dtm() {
    StandAloneDataTypeManager mgr("test_fd_clone");
    FunctionDefinitionDataType f("fn", &mgr);
    f.setReturnType(&IntegerDataType::dataType());
    DataType* c = f.clone(&mgr);
    TEST("fd.clone.same", c == &f);
    if (c != &f) delete c;
}

void test_funcdef_isEquivalent() {
    FunctionDefinitionDataType f1("fn");
    FunctionDefinitionDataType f2("fn");
    f1.setReturnType(&IntegerDataType::dataType());
    f2.setReturnType(&IntegerDataType::dataType());
    ByteDataType b;
    TEST("fd.eq.same", f1.isEquivalent(&f2));
    TEST("fd.eq.null", !f1.isEquivalent(nullptr));
    TEST("fd.eq.dt", !f1.isEquivalent(&b));
    TEST("fd.eq.sig", f1.isEquivalentSignature(&f2));
}

// ---- ArrayDataType tests ----

void test_array_basic() {
    ArrayDataType a(&IntegerDataType::dataType(), 10);
    TEST("arr.numElements", a.getNumElements() == 10);
    TEST("arr.elementLength", a.getElementLength() == IntegerDataType::dataType().getLength());
    TEST("arr.length", a.getLength() == 10 * IntegerDataType::dataType().getLength());
    TEST("arr.dt", a.getDataType() == &IntegerDataType::dataType());
    TEST("arr.deleted", !a.isDeleted());
    TEST("arr.zeroLen", !a.isZeroLength());
}

void test_array_explicit_element_length() {
    ArrayDataType a(&IntegerDataType::dataType(), 5, 4);
    TEST("arr.elemLen.4", a.getElementLength() == 4);
    TEST("arr.length.20", a.getLength() == 20);
}

void test_array_zero_elements() {
    ArrayDataType a(&ByteDataType::dataType(), 0);
    TEST("arr.0elem.num", a.getNumElements() == 0);
    TEST("arr.0elem.len", a.getLength() == 1);
    TEST("arr.0elem.zero", a.isZeroLength());
}

void test_array_getCategoryPath() {
    ArrayDataType a(&ByteDataType::dataType(), 3);
    TEST("arr.catpath", a.getCategoryPath() == CategoryPath::ROOT());
}

void test_array_description() {
    ArrayDataType a(&IntegerDataType::dataType(), 4);
    auto desc = a.getDescription();
    TEST("arr.desc.notEmpty", !desc.empty());
}

void test_array_mnemonic() {
    ArrayDataType a(&IntegerDataType::dataType(), 4);
    auto m = a.getMnemonic(nullptr);
    TEST("arr.mn.notEmpty", !m.empty());
    TEST("arr.mn.contains.4", m.find("4") != std::string::npos);
}

void test_array_equivalent() {
    ArrayDataType a1(&IntegerDataType::dataType(), 5);
    ArrayDataType a2(&IntegerDataType::dataType(), 5);
    ArrayDataType a3(&IntegerDataType::dataType(), 6);
    ArrayDataType a4(&ByteDataType::dataType(), 5);
    TEST("arr.eq.same", a1.isEquivalent(&a2));
    TEST("arr.eq.difcount", !a1.isEquivalent(&a3));
    TEST("arr.eq.difdt", !a1.isEquivalent(&a4));
    TEST("arr.eq.null", !a1.isEquivalent(nullptr));
}

void test_array_dependsOn() {
    ArrayDataType a(&IntegerDataType::dataType(), 5);
    TEST("arr.dep.yes", a.dependsOn(&IntegerDataType::dataType()));
    TEST("arr.dep.no", !a.dependsOn(&ByteDataType::dataType()));
    TEST("arr.dep.null", !a.dependsOn(nullptr));
}

void test_array_label_prefix() {
    ArrayDataType a(&IntegerDataType::dataType(), 5);
    auto p = a.getDefaultLabelPrefix();
    TEST("arr.lp.notEmpty", !p.empty());
}

void test_array_clone_same_dtm() {
    StandAloneDataTypeManager mgr("test_arr_clone");
    ArrayDataType a(&IntegerDataType::dataType(), 5, -1, &mgr);
    DataType* c = a.clone(&mgr);
    TEST("arr.clone.same", c == &a);
    if (c != &a) delete c;
}

void test_array_hasLangDep() {
    ArrayDataType a(&IntegerDataType::dataType(), 5);
    TEST("arr.langDep", a.hasLanguageDependantLength());
    ArrayDataType b(&ByteDataType::dataType(), 5);
    TEST("arr.langDep.byte", !b.hasLanguageDependantLength());
}

// ---- DataTypeImpl tests ----

class TestDataTypeImpl : public DataTypeImpl {
public:
    TestDataTypeImpl(const std::string& name, DataTypeManager* mgr = nullptr)
        : DataTypeImpl(CategoryPath::ROOT(), name, mgr) {}
    DataType* clone(DataTypeManager* dtm) const override {
        if (getDataTypeManager() == dtm) return const_cast<TestDataTypeImpl*>(this);
        return new TestDataTypeImpl(getName(), dtm);
    }
    DataType* copy(DataTypeManager* dtm) const override { return clone(dtm); }
    int getLength() const override { return 4; }
    std::string getDescription() const override { return "TestDataTypeImpl"; }
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override {
        return std::to_string(length);
    }
    bool isEncodable() const override { return false; }
    std::vector<uint8_t> encodeValue(void* value, MemBuffer* buf, Settings* settings, int length) const override {
        return {};
    }
    const std::type_info& getValueClass(Settings* settings) const override { return typeid(void); }
    std::vector<uint8_t> encodeRepresentation(const std::string& repr, MemBuffer* buf, Settings* settings, int length) const override {
        return {};
    }
};

void test_dti_basics() {
    TestDataTypeImpl t("t1");
    TEST("dti.name", t.getName() == "t1");
    TEST("dti.length", t.getLength() == 4);
    TEST("dti.cat", t.getCategoryPath() == CategoryPath::ROOT());
    TEST("dti.settings.null", t.getDefaultSettings() == nullptr);
    TEST("dti.settingsDefs.empty", t.getSettingsDefinitions().empty());
    TEST("dti.lastChange.zero", t.getLastChangeTime() == AbstractDataType::NO_LAST_CHANGE_TIME);
    TEST("dti.lastChangeSA.zero", t.getLastChangeTimeInSourceArchive() == AbstractDataType::NO_LAST_CHANGE_TIME);
    TEST("dti.archive.null", t.getSourceArchive() == nullptr);
    TEST("dti.parents.empty", t.getParents().empty());
    TEST("dti.aligned.ge1", t.getAlignedLength() >= 1);
    TEST("dti.alignment.ge1", t.getAlignment() >= 1);
}

void test_dti_lastChange_setters() {
    TestDataTypeImpl t("t");
    t.setLastChangeTime(12345LL);
    TEST("dti.setLCT", t.getLastChangeTime() == 12345LL);
    t.setLastChangeTimeInSourceArchive(67890LL);
    TEST("dti.setLCTSA", t.getLastChangeTimeInSourceArchive() == 67890LL);
}

void test_dti_sourceArchive_setter() {
    TestDataTypeImpl t("t");
    SourceArchiveImpl sa(UniversalID(1), ArchiveType::FILE, "ar");
    t.setSourceArchive(&sa);
    TEST("dti.sa.set", t.getSourceArchive() == &sa);
}

void test_dti_parents() {
    TestDataTypeImpl t("t");
    TestDataTypeImpl p1("p1");
    TestDataTypeImpl p2("p2");
    t.addParent(&p1);
    t.addParent(&p2);
    auto parents = t.getParents();
    TEST("dti.parents.size", parents.size() == 2);
    TEST("dti.parents[0]", parents[0] == &p1);
    TEST("dti.parents[1]", parents[1] == &p2);
    t.removeParent(&p1);
    auto after = t.getParents();
    TEST("dti.parents.after.size", after.size() == 1);
    TEST("dti.parents.after[0]", after[0] == &p2);
    t.addParent(nullptr);
    TEST("dti.parents.nullAdd", t.getParents().size() == 1);
}

void test_dti_setDescription_throws() {
    TestDataTypeImpl t("t");
    bool threw = false;
    try { t.setDescription("desc"); }
    catch (const std::exception&) { threw = true; }
    TEST("dti.setDesc.throws", threw);
}

void test_dti_isEquivalent() {
    TestDataTypeImpl t1("t");
    TestDataTypeImpl t2("t");
    TEST("dti.eq.same", t1.isEquivalent(&t2));
    TEST("dti.eq.self", t1.isEquivalent(&t1));
    TEST("dti.eq.null", !t1.isEquivalent(nullptr));
    ArrayDataType a(&IntegerDataType::dataType(), 3);
    TEST("dti.eq.diff", !t1.isEquivalent(&a));
}

void test_dti_valueClass() {
    TestDataTypeImpl t("t");
    TEST("dti.vc", t.getValueClass(nullptr) == typeid(void));
}

void test_dti_clone_same() {
    StandAloneDataTypeManager mgr("test_dti");
    TestDataTypeImpl t("t", &mgr);
    DataType* c = t.clone(&mgr);
    TEST("dti.clone.same", c == &t);
    if (c != &t) delete c;
}

} // namespace

int main() {
    // UniversalID
    test_universal_id();
    // ArchiveTypeUtil
    test_archive_type_util();
    // SourceArchiveImpl
    test_source_archive_2arg();
    test_source_archive_4arg();
    test_source_archive_6arg();
    test_source_archive_setters();
    // DataTypeConflictHandler
    test_conflict_handler_default();
    test_conflict_handler_keep();
    test_conflict_handler_replace();
    test_conflict_handler_empty_struct();
    test_conflict_handler_empty_union();
    test_conflict_handler_builtin_throws();
    test_conflict_handler_getHandler();
    // DataTypePath
    test_datatype_path_string_ctor();
    test_datatype_path_category_ctor();
    test_datatype_path_eq();
    test_datatype_path_compare();
    test_datatype_path_isAncestor();
    test_datatype_path_hash();
    // ParameterDefinitionImpl
    test_param_def_basic();
    test_param_def_setters();
    test_param_def_equivalent();
    test_param_def_toString();
    // FunctionDefinitionDataType
    test_funcdef_default();
    test_funcdef_set_return_type();
    test_funcdef_set_comment();
    test_funcdef_set_var_args();
    test_funcdef_set_noreturn();
    test_funcdef_set_cconv();
    test_funcdef_set_arguments();
    test_funcdef_prototype_string();
    test_funcdef_prototype_void();
    test_funcdef_prototype_varargs();
    test_funcdef_clone_same_dtm();
    test_funcdef_isEquivalent();
    // ArrayDataType
    test_array_basic();
    test_array_explicit_element_length();
    test_array_zero_elements();
    test_array_getCategoryPath();
    test_array_description();
    test_array_mnemonic();
    test_array_equivalent();
    test_array_dependsOn();
    test_array_label_prefix();
    test_array_clone_same_dtm();
    test_array_hasLangDep();
    // DataTypeImpl
    test_dti_basics();
    test_dti_lastChange_setters();
    test_dti_sourceArchive_setter();
    test_dti_parents();
    test_dti_setDescription_throws();
    test_dti_isEquivalent();
    test_dti_valueClass();
    test_dti_clone_same();

    std::cout << "Batch U: " << passed << "/" << total << " passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
