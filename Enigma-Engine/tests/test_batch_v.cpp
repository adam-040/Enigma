/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_v.cpp
/// \brief Tests for Batch V: DataTypeWriter (file-level data type I/O).
///
/// DataTypeTransferable (Java AWT) and FileDataTypeManager (PackedDatabase
/// on disk) are deliberately not ported — see AGENTS.md for the
/// database/* skip policy.
#include <ghidra/DataTypeWriter.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/StandAloneDataTypeManager.h>
#include <ghidra/TaskMonitor.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

std::string writeType(DataType* dt) {
    std::ostringstream os;
    DataTypeWriter w(nullptr, os);
    w.write(dt);
    return os.str();
}

std::string writeType(DataTypeManager* mgr, DataType* dt) {
    std::ostringstream os;
    DataTypeWriter w(mgr, os);
    w.write(dt);
    return os.str();
}

std::string writeMany(DataTypeManager* mgr,
                      const std::vector<DataType*>& types) {
    std::ostringstream os;
    DataTypeWriter w(mgr, os);
    w.write(types);
    return os.str();
}

void test_writer_basic_struct() {
    StructureDataType s("S", 0);
    s.add(&ByteDataType::dataType());
    s.add(&IntegerDataType::dataType(), "x", "an int field");
    std::string out = writeType(&s);
    TEST("struct.forward", out.find("struct S;") != std::string::npos);
    TEST("struct.def",     out.find("struct S {") != std::string::npos);
    TEST("struct.closer",  out.find("};") != std::string::npos);
    TEST("struct.field",   out.find("x") != std::string::npos);
    TEST("struct.comment", out.find("an int field") != std::string::npos);
}

void test_writer_basic_union() {
    UnionDataType u("U", 0);
    u.add(&ByteDataType::dataType(), "a", "");
    u.add(&WordDataType::dataType(), "b", "");
    std::string out = writeType(&u);
    TEST("union.forward", out.find("union U;") != std::string::npos);
    TEST("union.def",     out.find("union U {") != std::string::npos);
    TEST("union.closer",  out.find("};") != std::string::npos);
    TEST("union.field_a", out.find("a") != std::string::npos);
    TEST("union.field_b", out.find("b") != std::string::npos);
}

void test_writer_basic_enum() {
    EnumDataType e("E", 1);
    e.add("A", 0);
    e.add("B", 1);
    e.add("C", 2);
    std::string out = writeType(&e);
    TEST("enum.def",   out.find("enum E {") != std::string::npos);
    TEST("enum.A",     out.find("A = 0") != std::string::npos);
    TEST("enum.B",     out.find("B = 1") != std::string::npos);
    TEST("enum.C",     out.find("C = 2") != std::string::npos);
    TEST("enum.closer",out.find("} E;") != std::string::npos);
}

void test_writer_basic_typedef() {
    TypedefDataType t("MyInt", &IntegerDataType::dataType());
    std::string out = writeType(&t);
    TEST("typedef.alias", out.find("typedef") != std::string::npos);
    TEST("typedef.name",  out.find("MyInt") != std::string::npos);
}

void test_writer_basic_pointer() {
    PointerDataType p(&IntegerDataType::dataType(), 4);
    std::string out = writeType(&p);
    TEST("ptr.star",   out.find("*") != std::string::npos);
    TEST("ptr.typedef",out.find("typedef") != std::string::npos);
}

void test_writer_basic_array() {
    ArrayDataType a(&ByteDataType::dataType(), 10);
    std::string out = writeType(&a);
    TEST("array.bracket",  out.find("[10]") != std::string::npos);
    TEST("array.typedef",  out.find("typedef") != std::string::npos);
}

void test_writer_nested_struct() {
    StructureDataType inner("Inner", 0);
    inner.add(&IntegerDataType::dataType(), "v", "");

    StructureDataType outer("Outer", 0);
    outer.add(&inner, "in", "");

    std::string out = writeType(&outer);
    TEST("nested.fwd_inner", out.find("struct Inner;") != std::string::npos);
    TEST("nested.fwd_outer", out.find("struct Outer;") != std::string::npos);
    TEST("nested.def_inner", out.find("struct Inner {") != std::string::npos);
    TEST("nested.def_outer", out.find("struct Outer {") != std::string::npos);
    TEST("nested.field",     out.find("in") != std::string::npos);
}

void test_writer_recursive_struct() {
    // struct Node { struct Node* next; int v; };
    StructureDataType node("Node", 0);
    PointerDataType selfPtr(&node, 4);
    node.add(&selfPtr, "next", "");
    node.add(&IntegerDataType::dataType(), "v", "");

    std::string out = writeType(&node);
    TEST("recursive.fwd", out.find("struct Node;") != std::string::npos);
    TEST("recursive.def", out.find("struct Node {") != std::string::npos);
    TEST("recursive.next", out.find("next") != std::string::npos);
    TEST("recursive.v",    out.find("v") != std::string::npos);
}

void test_writer_typedef_of_struct() {
    StructureDataType s("S2", 0);
    s.add(&IntegerDataType::dataType(), "x", "");
    TypedefDataType t("S2_t", &s);

    std::string out = writeType(&t);
    TEST("tds.forward", out.find("struct S2;") != std::string::npos);
    TEST("tds.def",     out.find("struct S2 {") != std::string::npos);
    TEST("tds.typedef", out.find("S2_t") != std::string::npos);
}

void test_writer_enum_typedef() {
    EnumDataType e("E2", 1);
    e.add("X", 0);
    e.add("Y", 1);
    TypedefDataType t("E2_t", &e);
    std::string out = writeType(&t);
    TEST("etd.enumdef", out.find("enum E2 {") != std::string::npos);
    TEST("etd.X",       out.find("X = 0") != std::string::npos);
    TEST("etd.Y",       out.find("Y = 1") != std::string::npos);
    TEST("etd.typedef", out.find("E2_t") != std::string::npos);
}

void test_writer_function_pointer() {
    FunctionDefinitionDataType f("FnPtrT");
    f.setReturnType(&IntegerDataType::dataType());
    std::vector<ParameterDefinition*> args;
    args.push_back(new ParameterDefinitionImpl("x", &IntegerDataType::dataType(), "", 0, false));
    args.push_back(new ParameterDefinitionImpl("y", &ByteDataType::dataType(), "", 1, false));
    f.setArguments(args);
    for (auto* p : args) delete p;

    PointerDataType p(&f, 4);
    p.setName("FnPtrT_ptr");

    std::string out = writeType(&p);
    TEST("fp.typedef", out.find("typedef") != std::string::npos);
    TEST("fp.star",    out.find("(*") != std::string::npos);
    TEST("fp.parens",  out.find(")") != std::string::npos);
    TEST("fp.x_param", out.find("x") != std::string::npos);
    TEST("fp.y_param", out.find("y") != std::string::npos);
}

void test_writer_function_def_varargs() {
    FunctionDefinitionDataType f("VarFn");
    f.setReturnType(&IntegerDataType::dataType());
    f.setVarArgs(true);
    std::vector<ParameterDefinition*> args;
    args.push_back(new ParameterDefinitionImpl("a", &IntegerDataType::dataType(), "", 0, false));
    f.setArguments(args);
    for (auto* p : args) delete p;

    std::string out = writeType(&f);
    TEST("vf.typedef", out.find("typedef") != std::string::npos);
    TEST("vf.dots",    out.find("...") != std::string::npos);
}

void test_writer_function_def_void() {
    FunctionDefinitionDataType f("VoidFn");
    f.setReturnType(&VoidDataType::dataType());
    std::string out = writeType(&f);
    TEST("voidf.typedef", out.find("typedef") != std::string::npos);
    TEST("voidf.void",    out.find("void") != std::string::npos);
}

void test_writer_writeMany() {
    StructureDataType s("S3", 0);
    s.add(&IntegerDataType::dataType(), "a", "");
    UnionDataType u("U3", 0);
    u.add(&ByteDataType::dataType(), "b", "");

    std::vector<DataType*> types;
    types.push_back(&s);
    types.push_back(&u);

    std::string out = writeMany(nullptr, types);
    TEST("many.S", out.find("struct S3;") != std::string::npos);
    TEST("many.U", out.find("union U3;") != std::string::npos);
}

void test_writer_null_safety() {
    std::ostringstream os;
    DataTypeWriter w(nullptr, os);
    w.write(static_cast<DataType*>(nullptr)); // should be a no-op
    TEST("null.write", os.str().empty());
}

void test_writer_resolved_tracking() {
    StructureDataType s("S4", 0);
    s.add(&IntegerDataType::dataType(), "v", "");

    std::ostringstream os;
    DataTypeWriter w(nullptr, os);
    TEST("resolved.empty", !w.isResolved("S4"));
    w.write(&s);
    TEST("resolved.after", w.isResolved("S4"));
    TEST("resolved.count", w.resolvedCount() >= 1);
}

void test_writer_ctor_no_dtm() {
    std::ostringstream os;
    DataTypeWriter w(nullptr, os); // dtm == nullptr should not crash
    TEST("ctor.nodtm", w.resolvedCount() == 0);
}

void test_writer_ctor_with_dtm() {
    StandAloneDataTypeManager mgr("test_dtw_dtm");
    std::ostringstream os;
    DataTypeWriter w(&mgr, os);
    StructureDataType s("S5", 0);
    s.add(&IntegerDataType::dataType(), "v", "");
    w.write(&s);
    TEST("ctor.dtm", os.str().find("struct S5;") != std::string::npos);
}

void test_writer_cpp_comments() {
    StructureDataType s("Sc", 0);
    s.add(&IntegerDataType::dataType(), "x", "a comment");

    std::ostringstream os;
    DataTypeWriter w(nullptr, os, /*cppStyleComments=*/true);
    w.write(&s);
    std::string out = os.str();
    TEST("cpp.cpp_comment", out.find("// a comment") != std::string::npos);
    TEST("cpp.no_c_comment", out.find("/* a comment */") == std::string::npos);
}

void test_writer_c_comments_default() {
    StructureDataType s("Sc2", 0);
    s.add(&IntegerDataType::dataType(), "x", "a comment");
    std::ostringstream os;
    DataTypeWriter w(nullptr, os);
    w.write(&s);
    std::string out = os.str();
    TEST("cstyle.default", out.find("/* a comment */") != std::string::npos);
    TEST("cstyle.no_cpp",  out.find("// a comment") == std::string::npos);
}

void test_writer_eol_constant() {
    TEST("eol.value", DataTypeWriter::EOL == "\n");
}

void test_writer_no_duplicate_def() {
    // Writing the same type twice should not duplicate definitions.
    StructureDataType s("Dup", 0);
    s.add(&IntegerDataType::dataType(), "v", "");

    std::ostringstream os;
    DataTypeWriter w(nullptr, os);
    w.write(&s);
    size_t after_first = os.str().size();
    w.write(&s); // should be a no-op
    size_t after_second = os.str().size();
    TEST("nodup.idempotent", after_first == after_second);
}

void test_writer_primitive_only() {
    // A plain integer: the writer may produce a minimal alias line for it
    // (IntegerDataType is treated as a known primitive). The key property is
    // that it doesn't produce a struct or composite declaration.
    std::string out = writeType(&IntegerDataType::dataType());
    TEST("prim.no_struct_decl", out.find("struct") == std::string::npos);
    TEST("prim.no_brace",       out.find("{") == std::string::npos);
}

void test_writer_eol_in_output() {
    StructureDataType s("SL", 0);
    s.add(&IntegerDataType::dataType(), "v", "");
    std::string out = writeType(&s);
    TEST("eol.appears", out.find("\n") != std::string::npos);
}

void test_writer_function_def_direct() {
    FunctionDefinitionDataType f("FuncT");
    f.setReturnType(&IntegerDataType::dataType());
    std::string out = writeType(&f);
    TEST("fd.direct", out.find("typedef") != std::string::npos);
}

void test_writer_enum_in_struct() {
    EnumDataType e("Mode", 1);
    e.add("OFF", 0);
    e.add("ON", 1);
    StructureDataType s("Cfg", 0);
    s.add(&e, "mode", "");
    std::string out = writeType(&s);
    TEST("ein.fwd", out.find("enum Mode;") != std::string::npos);
    TEST("ein.def", out.find("enum Mode {") != std::string::npos);
    TEST("ein.OFF", out.find("OFF = 0") != std::string::npos);
    TEST("ein.field", out.find("mode") != std::string::npos);
}

void test_writer_pointer_chain() {
    PointerDataType p1(&IntegerDataType::dataType(), 4);
    PointerDataType p2(&p1, 4);
    std::string out = writeType(&p2);
    TEST("pchain.stars",   out.find("**") != std::string::npos);
    TEST("pchain.no_typedef_only_inner",
         out.find("typedef") != std::string::npos);
}

void test_writer_struct_with_array_field() {
    StructureDataType s("Buffer", 0);
    ArrayDataType a(&ByteDataType::dataType(), 256);
    s.add(&a, "data", "");
    std::string out = writeType(&s);
    TEST("swarr.fwd_arr", out.find("[256]") != std::string::npos);
    TEST("swarr.field",   out.find("data") != std::string::npos);
}

void test_writer_union_with_struct_field() {
    StructureDataType s("Coord", 0);
    s.add(&IntegerDataType::dataType(), "x", "");
    s.add(&IntegerDataType::dataType(), "y", "");
    UnionDataType u("Uloc", 0);
    u.add(&s, "loc", "");
    std::string out = writeType(&u);
    TEST("us.fwd", out.find("struct Coord;") != std::string::npos);
    TEST("us.def", out.find("struct Coord {") != std::string::npos);
    TEST("us.udef", out.find("union Uloc {") != std::string::npos);
    TEST("us.field", out.find("loc") != std::string::npos);
}

void test_writer_double_field() {
    StructureDataType s("D", 0);
    s.add(&DWordDataType::dataType(), "v", "");
    std::string out = writeType(&s);
    TEST("dfield.fwd", out.find("struct D;") != std::string::npos);
    TEST("dfield.def", out.find("struct D {") != std::string::npos);
}

} // namespace

int main() {
    test_writer_basic_struct();
    test_writer_basic_union();
    test_writer_basic_enum();
    test_writer_basic_typedef();
    test_writer_basic_pointer();
    test_writer_basic_array();
    test_writer_nested_struct();
    test_writer_recursive_struct();
    test_writer_typedef_of_struct();
    test_writer_enum_typedef();
    test_writer_function_pointer();
    test_writer_function_def_varargs();
    test_writer_function_def_void();
    test_writer_writeMany();
    test_writer_null_safety();
    test_writer_resolved_tracking();
    test_writer_ctor_no_dtm();
    test_writer_ctor_with_dtm();
    test_writer_cpp_comments();
    test_writer_c_comments_default();
    test_writer_eol_constant();
    test_writer_no_duplicate_def();
    test_writer_primitive_only();
    test_writer_eol_in_output();
    test_writer_function_def_direct();
    test_writer_enum_in_struct();
    test_writer_pointer_chain();
    test_writer_struct_with_array_field();
    test_writer_union_with_struct_field();
    test_writer_double_field();

    std::cout << "Batch V: " << passed << "/" << total << " passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
