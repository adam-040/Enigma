/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_k.cpp
/// \brief Tests for batch K: model.pcode HighFunction family.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"
#include "ghidra/Address.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/DefaultAddressFactory.h"
#include "ghidra/MutabilitySettingsDefinition.h"
#include "ghidra/HighSymbol.h"
#include "ghidra/SymbolEntry.h"
#include "ghidra/MappedEntry.h"
#include "ghidra/DynamicEntry.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/Varnode.h"
#include "ghidra/PcodeOp.h"
#include "ghidra/pcode/HighVariable.h"
#include "ghidra/pcode/HighParam.h"
#include "ghidra/pcode/HighLocal.h"
#include "ghidra/pcode/HighGlobal.h"
#include "ghidra/pcode/HighConstant.h"
#include "ghidra/pcode/HighOther.h"
#include "ghidra/pcode/HighCodeSymbol.h"
#include "ghidra/pcode/HighLabelSymbol.h"
#include "ghidra/pcode/HighFunctionSymbol.h"
#include "ghidra/pcode/HighFunctionShellSymbol.h"
#include "ghidra/pcode/HighExternalSymbol.h"
#include "ghidra/pcode/HighParamID.h"
#include "ghidra/pcode/EquateSymbol.h"
#include "ghidra/pcode/HighFunction.h"
#include "ghidra/pcode/FunctionPrototype.h"
#include "ghidra/DataTypeSymbol.h"
#include "ghidra/EquateTable.h"
#include "ghidra/EquateTableImpl.h"
#include "ghidra/TypeDef.h"
#include "ghidra/PcodeSyntaxTree.h"
#include "ghidra/LocalSymbolMap.h"
#include "ghidra/GlobalSymbolMap.h"

namespace {

int passed = 0;
int total = 0;

#define TEST(name, expr) do { \
    ++total; \
    if (expr) { \
        std::cout << "[PASS] " << name << "\n" << std::flush; \
        ++passed; \
    } else { \
        std::cout << "[FAIL] " << name << "\n" << std::flush; \
    } \
} while (0)

using namespace ghidra;
namespace PC = ghidra::pcode;

static AddressFactory* makeTestFactory() {
    static DefaultAddressFactory factory;
    return &factory;
}

static GenericAddressSpace* ramSpace() {
    static GenericAddressSpace sp("ram", 32, AddressSpace::TYPE_RAM, 0);
    return &sp;
}

static GenericAddressSpace* constSpace() {
    static GenericAddressSpace sp("const", 32, AddressSpace::TYPE_CONSTANT, 1);
    return &sp;
}

static void test_high_symbol_base() {
    HighSymbol s(42, "alpha", nullptr, nullptr);
    TEST("TestHighSymbol.base.id", s.getId() == 42);
    TEST("TestHighSymbol.base.name", s.getName() == "alpha");
    TEST("TestHighSymbol.base.locks.default", !s.isTypeLocked() && !s.isNameLocked());
    TEST("TestHighSymbol.base.category.default", s.getCategory() == -1);
    s.setName("beta");
    TEST("TestHighSymbol.base.rename", s.getName() == "beta");
    s.setNameLock(true);
    s.setTypeLock(true);
    TEST("TestHighSymbol.base.locks.set", s.isNameLocked() && s.isTypeLocked());
    s.setCategory(0, 2);
    TEST("TestHighSymbol.base.category.set", s.getCategory() == 0 && s.getCategoryIndex() == 2);
    TEST("TestHighSymbol.base.isParam", s.isParameter());
    TEST("TestHighSymbol.base.isThisPtr.default", !s.isThisPointer());
    s.setThisPointer(true);
    TEST("TestHighSymbol.base.isThisPtr.set", s.isThisPointer());
    TEST("TestHighSymbol.base.size.noEntries", s.getSize() == 0);
    TEST("TestHighSymbol.base.mutability.default", s.getMutability() == MutabilitySettingsDefinition::NORMAL);
    TEST("TestHighSymbol.base.global.default", !s.isGlobal());
}

static void test_high_variable_abstract() {
    Varnode vn(Address(ramSpace(), 0x10), 8);
    PC::HighParam p(1, "p1", &vn, 0, true, 0, 0, nullptr);
    PC::HighVariable* hv = &p;
    TEST("TestHighVariable.abstract.instance", hv != nullptr);
    TEST("TestHighVariable.abstract.getInstanceNumber", hv->getInstanceNumber() == 0);
    TEST("TestHighVariable.abstract.isReadOnly", hv->isReadOnly());
    TEST("TestHighVariable.abstract.isVolatile", !hv->isVolatile());
    TEST("TestHighVariable.abstract.isWritable", !hv->isWritable());
    TEST("TestHighVariable.abstract.getName", hv->getName() == "p1");
    TEST("TestHighVariable.abstract.getSize", hv->getSize() == 8);
    TEST("TestHighVariable.abstract.getSymbol", hv->getSymbol() == nullptr);
    TEST("TestHighVariable.abstract.getRepresent", hv->getRepresentative() == &vn);
    TEST("TestHighVariable.abstract.getType", hv->getDataType() == nullptr);
    hv->setDataTypeRaw(nullptr);
    hv->setName("renamed");
    TEST("TestHighVariable.abstract.setName", hv->getName() == "renamed");
}

static void test_high_param() {
    Varnode vn(Address(ramSpace(), 0x20), 4);
    PC::HighParam p(2, "arg0", &vn, 1, true, 4, 0, nullptr);
    TEST("TestHighParam.slot", p.getSlot() == 4);
    TEST("TestHighParam.size", p.getSize() == 4);
    TEST("TestHighParam.isParam", p.isParameter());
    TEST("TestHighParam.isConstant", !p.isConstant());
    TEST("TestHighParam.isReadOnly", p.isReadOnly());
    TEST("TestHighParam.cat", p.getCategory() == 1);
    TEST("TestHighParam.catIndex", p.getCategoryIndex() == 0);
    p.setName("renamed_param");
    TEST("TestHighParam.setName", p.getName() == "renamed_param");
    p.setSlot(7);
    TEST("TestHighParam.setSlot", p.getSlot() == 7);
    p.setHiddenReturnParam(true);
    TEST("TestHighParam.isHiddenReturn", p.isHiddenReturn());
}

static void test_high_local() {
    Varnode vn(Address(ramSpace(), 0x30), 4);
    PC::HighLocal l(3, "local_x", &vn, 5, false, 1, 0, nullptr);
    TEST("TestHighLocal.slot", l.getSlot() == 1);
    TEST("TestHighLocal.size", l.getSize() == 4);
    TEST("TestHighLocal.isParam", !l.isParameter());
    TEST("TestHighLocal.isConstant", !l.isConstant());
    TEST("TestHighLocal.isReadOnly", !l.isReadOnly());
    TEST("TestHighLocal.cat", l.getCategory() == 5);
}

static void test_high_global() {
    Varnode vn(Address(ramSpace(), 0x1000), 8);
    PC::HighGlobal g(4, "global_v", &vn, 6, true, 0x1000, nullptr);
    TEST("TestHighGlobal.addr", g.getAddr().getOffset() == 0x1000);
    TEST("TestHighGlobal.isParam", !g.isParameter());
    TEST("TestHighGlobal.isConstant", !g.isConstant());
    TEST("TestHighGlobal.isReadOnly", g.isReadOnly());
    TEST("TestHighGlobal.isGlobal", g.isGlobal());
    g.setReadOnly(false);
    TEST("TestHighGlobal.unsetReadOnly", !g.isReadOnly());
}

static void test_high_constant() {
    Varnode vn(Address(constSpace(), 0x12345678), 8);
    PC::HighConstant c(5, "K", &vn, 7, 0x12345678, nullptr);
    TEST("TestHighConstant.value", c.getScalarValue() == static_cast<int64_t>(0x12345678));
    TEST("TestHighConstant.isConstant", c.isConstant());
    TEST("TestHighConstant.isReadOnly", c.isReadOnly());
    TEST("TestHighConstant.isGlobal", !c.isGlobal());
    TEST("TestHighConstant.getName", c.getName() == "K");
}

static void test_high_other() {
    Varnode vn(Address(ramSpace(), 0x40), 8);
    PC::HighOther o(6, "sp", &vn, 8, 2, nullptr);
    TEST("TestHighOther.size", o.getSize() == 8);
    TEST("TestHighOther.slot", o.getSlot() == 2);
    TEST("TestHighOther.isParam", !o.isParameter());
    TEST("TestHighOther.isConstant", !o.isConstant());
}

static void test_high_code_symbol() {
    PC::HighCodeSymbol cs(7, "code1", nullptr, nullptr);
    TEST("TestHighCodeSymbol.id", cs.getId() == 7);
    TEST("TestHighCodeSymbol.locks", cs.isNameLocked() && cs.isTypeLocked());
    TEST("TestHighCodeSymbol.size", cs.getSize() == 1);
    HighSymbol* base = &cs;
    TEST("TestHighCodeSymbol.subclass", base->getId() == 7);
}

static void test_high_label_symbol() {
    PC::HighLabelSymbol ls("label1", Address(ramSpace(), 0x2000), nullptr);
    TEST("TestHighLabelSymbol.name", ls.getName() == "label1");
    TEST("TestHighLabelSymbol.locks", ls.isNameLocked() && ls.isTypeLocked());
    TEST("TestHighLabelSymbol.size", ls.getSize() == 1);
}

static void test_high_function_symbol() {
    PC::HighFunctionSymbol fs(Address(ramSpace(), 0x3000), 100, nullptr);
    TEST("TestHighFunctionSymbol.size", fs.getSize() == 100);
    TEST("TestHighFunctionSymbol.locks", fs.isNameLocked() && fs.isTypeLocked());
}

static void test_high_function_shell_symbol() {
    PC::HighFunctionShellSymbol fss(10, "shell1", Address(ramSpace(), 0x4000), nullptr);
    TEST("TestHighFunctionShellSymbol.name", fss.getName() == "shell1");
    TEST("TestHighFunctionShellSymbol.id", fss.getId() == 10);
    TEST("TestHighFunctionShellSymbol.locks", fss.isNameLocked() && fss.isTypeLocked());
}

static void test_high_external_symbol() {
    PC::HighExternalSymbol es("ext1", Address(ramSpace(), 0x5000), Address(ramSpace(), 0x6000), nullptr);
    TEST("TestHighExternalSymbol.resolveAddr", es.getResolveAddress().getOffset() == 0x6000);
    TEST("TestHighExternalSymbol.size", es.getSize() == 0);
    TEST("TestHighExternalSymbol.cat", es.getCategory() == -1);
}

static void test_high_param_id() {
    PC::HighParamID pid;
    TEST("TestHighParamID.default.func", pid.getFunction() == nullptr);
    TEST("TestHighParamID.default.extrapop", pid.getProtoExtraPop() == -1);
    TEST("TestHighParamID.default.numInputs", pid.getNumInputs() == 0);
    TEST("TestHighParamID.default.numOutputs", pid.getNumOutputs() == 0);
    TEST("TestHighParamID.default.model", pid.getModelName().empty());
    TEST("TestHighParamID.default.funcname", pid.getFunctionName().empty());
    pid.setFunctionName("foo");
    pid.setModelName("model_x86");
    pid.setProtoExtraPop(4);
    TEST("TestHighParamID.set.funcname", pid.getFunctionName() == "foo");
    TEST("TestHighParamID.set.model", pid.getModelName() == "model_x86");
    TEST("TestHighParamID.set.extrapop", pid.getProtoExtraPop() == 4);
    PC::HighParamID pid2((void*)0x1234, nullptr, nullptr, nullptr);
    TEST("TestHighParamID.ctor.func", pid2.getFunction() == (void*)0x1234);
}

static void test_equate_symbol() {
    PC::EquateSymbol es(20, "twok", 2048, nullptr, Address(ramSpace(), 0x7000), 0xabcd);
    TEST("TestEquateSymbol.id", es.getId() == 20);
    TEST("TestEquateSymbol.name", es.getName() == "twok");
    TEST("TestEquateSymbol.value", es.getValue() == 2048);
    TEST("TestEquateSymbol.convert.default", es.getConvert() == PC::EquateSymbol::FORMAT_DEFAULT);
    TEST("TestEquateSymbol.cat", es.getCategory() == 1);
    PC::EquateSymbol es2(21, PC::EquateSymbol::FORMAT_HEX, 0xCAFE, nullptr, Address(ramSpace(), 0x8000), 0);
    TEST("TestEquateSymbol.fmt.hex", es2.getConvert() == PC::EquateSymbol::FORMAT_HEX);
    TEST("TestEquateSymbol.fmt.value", es2.getValue() == 0xCAFE);
    TEST("TestEquateSymbol.fmt.noName", es2.getName().empty());
    TEST("TestEquateSymbol.formatString.hex", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_HEX) == "hex");
    TEST("TestEquateSymbol.formatString.dec", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_DEC) == "dec");
    TEST("TestEquateSymbol.formatString.oct", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_OCT) == "oct");
    TEST("TestEquateSymbol.formatString.bin", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_BIN) == "bin");
    TEST("TestEquateSymbol.formatString.char", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_CHAR) == "char");
    TEST("TestEquateSymbol.formatString.float", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_FLOAT) == "float");
    TEST("TestEquateSymbol.formatString.double", PC::EquateSymbol::getIntegerFormatString(PC::EquateSymbol::FORMAT_DOUBLE) == "double");
    TEST("TestEquateSymbol.formatString.default", PC::EquateSymbol::getIntegerFormatString(0) == "_");
    TEST("TestEquateSymbol.formatStringValue.hex", PC::EquateSymbol::getFormatStringValue("hex") == PC::EquateSymbol::FORMAT_HEX);
    TEST("TestEquateSymbol.formatStringValue.dec", PC::EquateSymbol::getFormatStringValue("dec") == PC::EquateSymbol::FORMAT_DEC);
    TEST("TestEquateSymbol.formatStringValue.oct", PC::EquateSymbol::getFormatStringValue("oct") == PC::EquateSymbol::FORMAT_OCT);
    TEST("TestEquateSymbol.formatStringValue.bin", PC::EquateSymbol::getFormatStringValue("bin") == PC::EquateSymbol::FORMAT_BIN);
    TEST("TestEquateSymbol.formatStringValue.char", PC::EquateSymbol::getFormatStringValue("char") == PC::EquateSymbol::FORMAT_CHAR);
    TEST("TestEquateSymbol.formatStringValue.float", PC::EquateSymbol::getFormatStringValue("float") == PC::EquateSymbol::FORMAT_FLOAT);
    TEST("TestEquateSymbol.formatStringValue.double", PC::EquateSymbol::getFormatStringValue("double") == PC::EquateSymbol::FORMAT_DOUBLE);
    TEST("TestEquateSymbol.formatStringValue.unknown", PC::EquateSymbol::getFormatStringValue("xx") == PC::EquateSymbol::FORMAT_DEFAULT);
    TEST("TestEquateSymbol.convertName.hex", PC::EquateSymbol::convertName("0xff", 0xff) == PC::EquateSymbol::FORMAT_HEX);
    TEST("TestEquateSymbol.convertName.dec", PC::EquateSymbol::convertName("42", 42) == PC::EquateSymbol::FORMAT_DEC);
    TEST("TestEquateSymbol.convertName.oct", PC::EquateSymbol::convertName("777o", 0777) == PC::EquateSymbol::FORMAT_OCT);
    TEST("TestEquateSymbol.convertName.bin", PC::EquateSymbol::convertName("1011b", 0xb) == PC::EquateSymbol::FORMAT_BIN);
    TEST("TestEquateSymbol.convertName.char", PC::EquateSymbol::convertName("'A'", 65) == PC::EquateSymbol::FORMAT_CHAR);
    TEST("TestEquateSymbol.convertName.empty", PC::EquateSymbol::convertName("", 0) == PC::EquateSymbol::FORMAT_DEFAULT);
}

static void test_data_type_symbol() {
    DataTypeSymbol dts(30, "mytypedef", nullptr, nullptr, Address(ramSpace(), 0x9000), 0x42);
    TEST("TestDataTypeSymbol.id", dts.getId() == 30);
    TEST("TestDataTypeSymbol.name", dts.getName() == "mytypedef");
    TEST("TestDataTypeSymbol.addr", dts.getAddress().getOffset() == 0x9000);
    TEST("TestDataTypeSymbol.hash", dts.getHash() == 0x42);
    TEST("TestDataTypeSymbol.size.zero", dts.getSize() == 0);
    TEST("TestDataTypeSymbol.storage.zero", dts.getStorageSize() == 0);
}

static void test_function_prototype() {
    PC::FunctionPrototype fp;
    TEST("TestFunctionPrototype.default.name", fp.getName().empty());
    TEST("TestFunctionPrototype.default.rettype", fp.getReturnType() == nullptr);
    TEST("TestFunctionPrototype.default.varArg", !fp.isVarArg());
    TEST("TestFunctionPrototype.default.hasThis", !fp.hasThisPointer());
    TEST("TestFunctionPrototype.default.inline", !fp.isInline());
    TEST("TestFunctionPrototype.default.noreturn", !fp.isNoReturn());
    TEST("TestFunctionPrototype.default.extrapop", fp.getExtrapop() == PC::FunctionPrototype::UNKNOWN_EXTRAPOP);
    TEST("TestFunctionPrototype.default.numParams", fp.getNumParams() == 0);
    fp.setName("foo");
    ghidra::DataType* dummyRet = (ghidra::DataType*)(uintptr_t)0x42;
    fp.setReturnType(dummyRet);
    fp.setVarArg(true);
    fp.setThisPointer(true);
    fp.setInline(true);
    fp.setNoReturn(true);
    fp.setExtrapop(8);
    fp.addParam("a", "int");
    fp.addParam("b", "char*");
    TEST("TestFunctionPrototype.set.name", fp.getName() == "foo");
    TEST("TestFunctionPrototype.set.rettype", fp.getReturnType() == dummyRet);
    TEST("TestFunctionPrototype.set.varArg", fp.isVarArg());
    TEST("TestFunctionPrototype.set.hasThis", fp.hasThisPointer());
    TEST("TestFunctionPrototype.set.inline", fp.isInline());
    TEST("TestFunctionPrototype.set.noreturn", fp.isNoReturn());
    TEST("TestFunctionPrototype.set.extrapop", fp.getExtrapop() == 8);
    TEST("TestFunctionPrototype.set.numParams", fp.getNumParams() == 2);
    TEST("TestFunctionPrototype.set.param0", fp.getParamName(0) == "a" && fp.getParamType(0) == "int");
    TEST("TestFunctionPrototype.set.param1", fp.getParamName(1) == "b" && fp.getParamType(1) == "char*");
}

static void test_high_function() {
    EquateTableImpl et;
    PC::HighFunction hf((void*)0x1111, nullptr, nullptr, nullptr, &et);
    TEST("TestHighFunction.func", hf.getFunction() == (void*)0x1111);
    TEST("TestHighFunction.equateTable", hf.getEquateTable() == &et);
    TEST("TestHighFunction.localMap", hf.getLocalSymbolMap() == nullptr);
    TEST("TestHighFunction.globalMap", hf.getGlobalSymbolMap() == nullptr);
    TEST("TestHighFunction.proto", hf.getFunctionPrototype() == nullptr);
    TEST("TestHighFunction.size.default", hf.getSize() == 0);
    hf.setSize(64);
    TEST("TestHighFunction.size.set", hf.getSize() == 64);
    PC::HighVariable* rv = (PC::HighVariable*)0x1234;
    hf.setReturn(rv);
    TEST("TestHighFunction.return", hf.getReturn() == rv);
    TEST("TestHighFunction.params.empty", hf.getParamList().empty());
    TEST("TestHighFunction.variables.empty", hf.getVariables().empty());
    hf.cleanSymbols();
    TEST("TestHighFunction.cleaned.return", hf.getReturn() == nullptr);
}

static void test_equate_table_interface() {
    EquateTableImpl et;
    Equate* e1 = et.createEquate("one", 1);
    Equate* e2 = et.createEquate("two", 2);
    TEST("TestEquateTable.create.count", et.getEquateCount() == 2);
    TEST("TestEquateTable.create.byName", et.getEquate("one") == e1);
    TEST("TestEquateTable.create.byValue", et.getEquate(2) == e2);
    std::vector<Equate*> all = et.getEquates();
    TEST("TestEquateTable.getEquates", all.size() == 2);
    Equate* e3 = et.createEquate("three", 3, Address(ramSpace(), 0x1234), 0);
    TEST("TestEquateTable.createAddr.count", et.getEquateCount() == 3);
    TEST("TestEquateTable.createAddr.byValue", et.getEquate(3) == e3);
    et.removeEquate(e2);
    TEST("TestEquateTable.remove.count", et.getEquateCount() == 2);
    TEST("TestEquateTable.remove.byName", et.getEquate("two") == nullptr);
    TEST("TestEquateTable.remove.byValue", et.getEquate(2) == nullptr);
    Equate* e4 = et.createEquate("four", 4);
    et.removeEquate(Address(ramSpace(), 0x1234), 0, 4);
    TEST("TestEquateTable.removeByAddrVal.count", et.getEquateCount() == 3);
    et.removeEquate(Address(ramSpace(), 0x1234), 0, 1);
    TEST("TestEquateTable.removeByAddrVal.noop", et.getEquateCount() == 3);
}

}  // namespace

int main() {
    test_high_symbol_base();
    test_high_variable_abstract();
    test_high_param();
    test_high_local();
    test_high_global();
    test_high_constant();
    test_high_other();
    test_high_code_symbol();
    test_high_label_symbol();
    test_high_function_symbol();
    test_high_function_shell_symbol();
    test_high_external_symbol();
    test_high_param_id();
    test_equate_symbol();
    test_data_type_symbol();
    test_function_prototype();
    test_high_function();
    test_equate_table_interface();

    std::cout << "\n[Batch K] " << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
