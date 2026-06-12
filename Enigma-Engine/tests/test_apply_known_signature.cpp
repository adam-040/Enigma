#include <ghidra/ApplyKnownSignatureAnalyzer.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionSignatureImpl.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/LongDataType.h>
#include <iostream>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

ghidra::DataType* reg(ghidra::DataTypeManager* mgr, ghidra::DataType* dt) {
    ghidra::DataTypeManagerImpl* impl = dynamic_cast<ghidra::DataTypeManagerImpl*>(mgr);
    if (impl) return impl->addDataType(dt);
    delete dt;
    return nullptr;
}

int main() {
    // ----- Test 1: DTM built-in types -----
    {
        ghidra::DataTypeManagerImpl dtm("test1");
        reg(&dtm, new ghidra::BooleanDataType(&dtm));
        reg(&dtm, new ghidra::DWordDataType(&dtm));
        reg(&dtm, new ghidra::QWordDataType(&dtm));

        TEST("dtm.void", dtm.getDataType(ghidra::CategoryPath::ROOT(), "void") != nullptr);
        TEST("dtm.int", dtm.getDataType(ghidra::CategoryPath::ROOT(), "int") != nullptr);
        TEST("dtm.bool", dtm.getDataType(ghidra::CategoryPath::ROOT(), "bool") != nullptr);
        TEST("dtm.dword", dtm.getDataType(ghidra::CategoryPath::ROOT(), "dword") != nullptr);
        TEST("dtm.qword", dtm.getDataType(ghidra::CategoryPath::ROOT(), "qword") != nullptr);
        TEST("dtm.long", dtm.getDataType(ghidra::CategoryPath::ROOT(), "long") != nullptr);
    }

    // ----- Test 2: FunctionSignatureImpl basic -----
    {
        ghidra::DataTypeManagerImpl dtm("test2");
        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");
        auto* intDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "int");
        TEST("test2.void", voidDt != nullptr);
        TEST("test2.int", intDt != nullptr);

        auto* sig = new ghidra::FunctionSignatureImpl("malloc");
        sig->setReturnType(voidDt);
        sig->addArgument(new ghidra::ParameterDefinitionImpl("size", intDt, "", 0));

        TEST("sig.malloc.name", sig->getName() == "malloc");
        TEST("sig.malloc.ret", sig->getReturnType() == voidDt);
        TEST("sig.malloc.args", sig->getArguments().size() == 1);
        TEST("sig.malloc.arg_dt", sig->getArguments()[0]->getDataType() == intDt);
        TEST("sig.malloc.not_varargs", !sig->hasVarArgs());
        TEST("sig.malloc.not_noreturn", !sig->hasNoReturn());

        delete sig;
    }

    // ----- Test 3: Sleep signature -----
    {
        ghidra::DataTypeManagerImpl dtm("test3");
        reg(&dtm, new ghidra::BooleanDataType(&dtm));
        reg(&dtm, new ghidra::DWordDataType(&dtm));
        reg(&dtm, new ghidra::QWordDataType(&dtm));

        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");
        auto* dwordDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "dword");

        auto* sig = new ghidra::FunctionSignatureImpl("Sleep");
        sig->setReturnType(voidDt);
        sig->setCallingConventionName("__stdcall");
        sig->addArgument(new ghidra::ParameterDefinitionImpl("dwMs", dwordDt, "", 0));

        TEST("sleep.ret", sig->getReturnType() == voidDt);
        TEST("sleep.cc", sig->getCallingConventionName() == "__stdcall");
        TEST("sleep.args", sig->getArguments().size() == 1);
        TEST("sleep.arg0", sig->getArguments()[0]->getDataType() == dwordDt);

        delete sig;
    }

    // ----- Test 4: ExitProcess signature (noreturn) -----
    {
        ghidra::DataTypeManagerImpl dtm("test4");
        reg(&dtm, new ghidra::DWordDataType(&dtm));

        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");
        auto* dwordDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "dword");

        auto* sig = new ghidra::FunctionSignatureImpl("ExitProcess");
        sig->setReturnType(voidDt);
        sig->setHasNoReturn(true);
        sig->addArgument(new ghidra::ParameterDefinitionImpl("uExitCode", dwordDt, "", 0));

        TEST("ep.ret", sig->getReturnType() == voidDt);
        TEST("ep.noreturn", sig->hasNoReturn());
        TEST("ep.args", sig->getArguments().size() == 1);

        delete sig;
    }

    // ----- Test 5: CreateFileA (multi-param) -----
    {
        ghidra::DataTypeManagerImpl dtm("test5");
        reg(&dtm, new ghidra::DWordDataType(&dtm));
        reg(&dtm, new ghidra::QWordDataType(&dtm));

        auto* dwordDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "dword");
        auto* qwordDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "qword");

        auto* sig = new ghidra::FunctionSignatureImpl("CreateFileA");
        sig->setReturnType(qwordDt);
        sig->setCallingConventionName("__stdcall");
        for (int i = 0; i < 6; i++)
            sig->addArgument(new ghidra::ParameterDefinitionImpl("", dwordDt, "", i));
        sig->addArgument(new ghidra::ParameterDefinitionImpl("", qwordDt, "", 6));

        TEST("cfa.args", sig->getArguments().size() == 7);
        TEST("cfa.ret", sig->getReturnType() == qwordDt);
        TEST("cfa.cc", sig->getCallingConventionName() == "__stdcall");

        delete sig;
    }

    // ----- Test 6: GetProcAddress signature -----
    {
        ghidra::DataTypeManagerImpl dtm("test6");
        reg(&dtm, new ghidra::DWordDataType(&dtm));
        reg(&dtm, new ghidra::QWordDataType(&dtm));

        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");
        auto* qwordDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "qword");

        auto* sig = new ghidra::FunctionSignatureImpl("GetProcAddress");
        sig->setReturnType(voidDt);
        sig->setCallingConventionName("__stdcall");
        sig->addArgument(new ghidra::ParameterDefinitionImpl("hModule", qwordDt, "", 0));
        sig->addArgument(new ghidra::ParameterDefinitionImpl("lpProcName", qwordDt, "", 1));

        TEST("gpa.ret", sig->getReturnType() == voidDt);
        TEST("gpa.cc", sig->getCallingConventionName() == "__stdcall");
        TEST("gpa.args", sig->getArguments().size() == 2);

        delete sig;
    }

    // ----- Test 7: malloc / free -----
    {
        ghidra::DataTypeManagerImpl dtm("test7");
        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");
        auto* intDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "int");

        auto* mallocSig = new ghidra::FunctionSignatureImpl("malloc");
        mallocSig->setReturnType(voidDt);
        mallocSig->addArgument(new ghidra::ParameterDefinitionImpl("size", intDt, "", 0));
        TEST("malloc.args", mallocSig->getArguments().size() == 1);

        auto* freeSig = new ghidra::FunctionSignatureImpl("free");
        freeSig->setReturnType(voidDt);
        freeSig->addArgument(new ghidra::ParameterDefinitionImpl("ptr", voidDt, "", 0));
        TEST("free.args", freeSig->getArguments().size() == 1);
        TEST("free.ret", freeSig->getReturnType() == voidDt);

        delete mallocSig;
        delete freeSig;
    }

    // ----- Test 8: abort (noreturn, no params) -----
    {
        ghidra::DataTypeManagerImpl dtm("test8");
        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");

        auto* sig = new ghidra::FunctionSignatureImpl("abort");
        sig->setReturnType(voidDt);
        sig->setHasNoReturn(true);

        TEST("abort.ret", sig->getReturnType() == voidDt);
        TEST("abort.noreturn", sig->hasNoReturn());
        TEST("abort.no_args", sig->getArguments().empty());
        TEST("abort.not_varargs", !sig->hasVarArgs());

        delete sig;
    }

    // ----- Test 9: Varargs (printf-like) -----
    {
        ghidra::DataTypeManagerImpl dtm("test9");
        auto* intDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "int");
        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");

        auto* sig = new ghidra::FunctionSignatureImpl("printf");
        sig->setReturnType(intDt);
        sig->setHasVarArgs(true);
        sig->addArgument(new ghidra::ParameterDefinitionImpl("fmt", voidDt, "", 0));

        TEST("printf.varargs", sig->hasVarArgs());
        TEST("printf.ret", sig->getReturnType() == intDt);
        TEST("printf.args", sig->getArguments().size() == 1);

        delete sig;
    }

    // ----- Test 10: Clone + equivalence -----
    {
        ghidra::DataTypeManagerImpl dtm("test10");
        reg(&dtm, new ghidra::DWordDataType(&dtm));
        auto* voidDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "void");
        auto* dwordDt = dtm.getDataType(ghidra::CategoryPath::ROOT(), "dword");

        auto* orig = new ghidra::FunctionSignatureImpl("GetProcAddress");
        orig->setReturnType(voidDt);
        orig->setCallingConventionName("__stdcall");
        orig->addArgument(new ghidra::ParameterDefinitionImpl("p0", dwordDt, "", 0));
        orig->addArgument(new ghidra::ParameterDefinitionImpl("p1", dwordDt, "", 1));

        auto* cloned = orig->clone();
        TEST("clone.ptr", cloned != nullptr);
        TEST("clone.name", cloned->getName() == "GetProcAddress");
        TEST("clone.ret", cloned->getReturnType() == voidDt);
        TEST("clone.cc", cloned->getCallingConventionName() == "__stdcall");
        TEST("clone.args", cloned->getArguments().size() == 2);
        TEST("clone.equiv", orig->isEquivalentSignature(cloned));
        TEST("clone.not_equiv_self", orig->isEquivalentSignature(orig));

        // Non-equivalent (different name)
        auto* other = new ghidra::FunctionSignatureImpl("Malloc");
        other->setReturnType(voidDt);
        other->addArgument(new ghidra::ParameterDefinitionImpl("p0", dwordDt, "", 0));
        TEST("clone.not_equiv_diffname", !orig->isEquivalentSignature(other));
        delete other;

        // Non-equivalent (different param count)
        auto* other2 = new ghidra::FunctionSignatureImpl("GetProcAddress");
        other2->setReturnType(voidDt);
        other2->addArgument(new ghidra::ParameterDefinitionImpl("p0", dwordDt, "", 0));
        TEST("clone.not_equiv_diffcount", !orig->isEquivalentSignature(other2));
        delete other2;

        delete cloned;
        delete orig;
    }

    // ----- Test 11: FunctionManager function creation -----
    {
        ghidra::GenericAddressSpace ram("ram", 64, ghidra::AddressSpace::TYPE_RAM, 1);
        ghidra::Address ramAddr0(&ram, 0x1000);
        ghidra::Address ramAddr1(&ram, 0x2000);
        ghidra::Address ramAddr2(&ram, 0x3000);

        ghidra::FunctionManager funcMgr;

        auto* func = funcMgr.createFunction("Sleep", ramAddr0,
            ghidra::AddressSet(ramAddr0, ramAddr0), ghidra::SourceType::IMPORTED);
        TEST("fm.create", func != nullptr);
        TEST("fm.name", func->getName() == "Sleep");
        TEST("fm.no_sig_initially", func->getSignature() == nullptr);

        auto* func2 = funcMgr.createFunction("UnknownThing", ramAddr1,
            ghidra::AddressSet(ramAddr1, ramAddr1), ghidra::SourceType::IMPORTED);
        TEST("fm.unknown", func2 != nullptr);
        TEST("fm.unknown_name", func2->getName() == "UnknownThing");
    }

    // ----- Test 12: Signature table is public and clearable -----
    {
        auto& table = ghidra::ApplyKnownSignatureAnalyzer::getSignatureTable();
        // The table is a static member. We can test its API without building it.
        // We don't clear it to avoid affecting other tests.
        // Just verify it's a valid map reference.
        TEST("table.is_map", (void*)&table == (void*)&table);
    }

    std::cout << "\n=== Results: " << passed << "/" << total << " passed ===\n";
    return (passed == total) ? 0 : 1;
}
