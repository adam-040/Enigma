/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file test_batch_o.cpp
/// \brief Tests for W~O: CompilerSpec expansion, BasicCompilerSpec.
#include <ghidra/CompilerSpec.h>
#include <ghidra/CompilerSpecDescription.h>
#include <ghidra/BasicCompilerSpec.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/SleighLanguageDescription.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/AddressFactory.h>
#include <iostream>
#include <string>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
    else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

namespace {

ghidra::GenericAddressSpace* testSpace() {
    static ghidra::GenericAddressSpace* sp = nullptr;
    if (!sp) sp = new ghidra::GenericAddressSpace("ram", 32, ghidra::AddressSpace::TYPE_RAM, 0);
    return sp;
}

void test_compiler_spec_properties() {
    CompilerSpec cs(CompilerSpecID("gcc"));
    TEST("CompilerSpec.default.props.empty", cs.getProperty("foo").empty());
    TEST("CompilerSpec.default.noHasProp", !cs.hasProperty("foo"));
    cs.setProperty("version", "1.0");
    cs.setProperty("arch", "x86");
    TEST("CompilerSpec.set.get", cs.getProperty("version") == "1.0");
    TEST("CompilerSpec.hasProp", cs.hasProperty("version"));
    TEST("CompilerSpec.getDefault", cs.getProperty("missing", "default") == "default");
    TEST("CompilerSpec.getDefault.empty", cs.getProperty("version", "default") == "1.0");
}

void test_compiler_spec_calling_conventions() {
    CompilerSpec cs;
    cs.setDefaultCallingConvention("__cdecl");
    TEST("CompilerSpec.defaultConv.null", cs.getDefaultCallingConvention() == nullptr);

    auto cdecl = std::make_unique<PrototypeModel>("__cdecl", "__cdecl");
    auto stdcall = std::make_unique<PrototypeModel>("__stdcall", "__stdcall");
    auto* cdeclPtr = cdecl.get();
    cs.addCallingConvention("__cdecl", std::move(cdecl));
    cs.addCallingConvention("__stdcall", std::move(stdcall));
    TEST("CompilerSpec.getCdecl", cs.getCallingConvention("__cdecl") == cdeclPtr);
    TEST("CompilerSpec.defaultConv.set", cs.getDefaultCallingConvention() == cdeclPtr);
    TEST("CompilerSpec.convNames.size", cs.getCallingConventionNames().size() == 2);
}

void test_compiler_spec_all_models() {
    CompilerSpec cs;
    TEST("CompilerSpec.allModels.default", cs.getAllModels().empty());
    TEST("CompilerSpec.callingConvs.default", cs.getCallingConventions().empty());
}

void test_basic_compiler_spec() {
    SleighLanguageDescription desc(
        LanguageID("x86:LE:32:default"), "x86 32-bit",
        Processor("x86"), Endian::LITTLE, Endian::LITTLE,
        32, "default", 1, 0
    );
    SleighLanguage lang(&desc);
    CompilerSpecDescription csDesc(CompilerSpecID("gcc"), "GCC", "builtin");

    BasicCompilerSpec bcs(&csDesc, &lang);
    TEST("BasicCompilerSpec.id", bcs.getCompilerSpecID().getIdAsString() == "gcc");
    TEST("BasicCompilerSpec.name", bcs.getName() == "GCC");
    TEST("BasicCompilerSpec.language", bcs.getLanguage() == &lang);
    TEST("BasicCompilerSpec.description", bcs.getCompilerSpecDescription() == &csDesc);
    TEST("BasicCompilerSpec.allModels.empty", bcs.getAllModels().empty());
    TEST("BasicCompilerSpec.callingConvs.empty", bcs.getCallingConventions().empty());
    TEST("BasicCompilerSpec.retAddr.null", bcs.getReturnAddress() == nullptr);
}

void test_basic_compiler_spec_context() {
    SleighLanguageDescription desc(
        LanguageID("x86:LE:32:default"), "x86 32-bit",
        Processor("x86"), Endian::LITTLE, Endian::LITTLE,
        32, "default", 1, 0
    );
    SleighLanguage lang(&desc);
    CompilerSpecDescription csDesc(CompilerSpecID("gcc"), "GCC", "builtin");
    BasicCompilerSpec bcs(&csDesc, &lang);

    TEST("BasicCompilerSpec.context.empty", bcs.getContextSettings().empty());
}

void test_basic_compiler_spec_match_convention() {
    SleighLanguageDescription desc(
        LanguageID("x86:LE:32:default"), "x86 32-bit",
        Processor("x86"), Endian::LITTLE, Endian::LITTLE,
        32, "default", 1, 0
    );
    SleighLanguage lang(&desc);
    CompilerSpecDescription csDesc(CompilerSpecID("gcc"), "GCC", "builtin");
    BasicCompilerSpec bcs(&csDesc, &lang);

    auto cdecl = std::make_unique<PrototypeModel>("__cdecl", "__cdecl");
    auto* cdeclPtr = cdecl.get();
    bcs.addCallingConvention("__cdecl", std::move(cdecl));
    bcs.setDefaultCallingConvention("__cdecl");

    TEST("BasicCompilerSpec.match.default", bcs.matchConvention("default") == cdeclPtr);
    TEST("BasicCompilerSpec.match.empty", bcs.matchConvention("") == cdeclPtr);
    TEST("BasicCompilerSpec.match.cdecl", bcs.matchConvention("__cdecl") == cdeclPtr);
    TEST("BasicCompilerSpec.match.unknown", bcs.matchConvention("unknown") == cdeclPtr);
    TEST("BasicCompilerSpec.match.missing", bcs.matchConvention("nonexistent") == cdeclPtr);
}

void test_compiler_spec_property_types() {
    CompilerSpec cs;
    cs.setProperty("version", "5");
    cs.setProperty("bigEndian", "true");
    cs.setProperty("size", "1024");

    TEST("CompilerSpec.prop.version", cs.getProperty("version") == "5");
    TEST("CompilerSpec.prop.bigEndian", cs.getProperty("bigEndian") == "true");
    TEST("CompilerSpec.prop.size", cs.getProperty("size") == "1024");
    TEST("CompilerSpec.prop.missing.empty", cs.getProperty("nope").empty());
}

void test_compiler_spec_copy() {
    CompilerSpec cs(CompilerSpecID("msvc"));
    cs.setName("MSVC");
    cs.setProperty("version", "14.0");
    cs.setStackGrowsNegative(false);
    cs.setAlignment(8);
    cs.setBigEndian(false);

    TEST("CompilerSpec.copy.id", cs.getCompilerSpecID().getIdAsString() == "msvc");
    TEST("CompilerSpec.copy.name", cs.getName() == "MSVC");
    TEST("CompilerSpec.copy.prop", cs.getProperty("version") == "14.0");
    TEST("CompilerSpec.copy.stackDir", !cs.isStackGrowsNegative());
    TEST("CompilerSpec.copy.align", cs.getAlignment() == 8);
    TEST("CompilerSpec.copy.endian", !cs.isBigEndian());
}

} // anonymous namespace

int main() {
    test_compiler_spec_properties();
    test_compiler_spec_calling_conventions();
    test_compiler_spec_all_models();
    test_basic_compiler_spec();
    test_basic_compiler_spec_context();
    test_basic_compiler_spec_match_convention();
    test_compiler_spec_property_types();
    test_compiler_spec_copy();

    std::cout << "\n[Batch O] " << passed << "/" << total << " tests passed\n";
    return (passed == total) ? 0 : 1;
}
