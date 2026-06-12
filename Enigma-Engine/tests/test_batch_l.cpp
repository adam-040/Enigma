#include <iostream>
#include <exception>
#include <vector>

#include "ghidra/pcode/PcodeException.h"
#include "ghidra/pcode/ParamMeasure.h"
#include "ghidra/pcode/JumpTable.h"
#include "ghidra/pcode/FunctionPrototype.h"
#include "ghidra/pcode/HighFunctionDBUtil.h"
#include "ghidra/VarnodeTranslator.h"
#include "ghidra/PcodeOverride.h"
#include "ghidra/Address.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/DefaultAddressFactory.h"
#include "ghidra/Varnode.h"
#include "ghidra/EquateTableImpl.h"

using namespace ghidra;
namespace PC = ghidra::pcode;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

static GenericAddressSpace* ramSpace() {
    static GenericAddressSpace sp("ram", 32, AddressSpace::TYPE_RAM, 0);
    return &sp;
}
static GenericAddressSpace* constSpace() {
    static GenericAddressSpace sp("const", 32, AddressSpace::TYPE_CONSTANT, 1);
    return &sp;
}

int main() {
    // PcodeException
    try {
        throw PC::PcodeException("test");
        TEST("PcodeException thrown", false);
    } catch (const std::runtime_error& e) {
        TEST("PcodeException is runtime_error", std::string(e.what()) == "Pcode: test");
    }

    // ParamMeasure
    {
        PC::ParamMeasure pm;
        TEST("ParamMeasure default rank", pm.getRank() == 0);
        TEST("ParamMeasure default empty", pm.isEmpty() == true);
        TEST("ParamMeasure type null default", pm.getDataType() == nullptr);
        TEST("ParamMeasure varnode null default", pm.getVarnode() == nullptr);
        pm.setRank(5);
        TEST("ParamMeasure setRank", pm.getRank() == 5);
        Address a(ramSpace(), 0x100);
        Varnode v(a, 4);
        pm.setVarnode(&v);
        TEST("ParamMeasure setVarnode non-null", pm.getVarnode() == &v);
        TEST("ParamMeasure non-empty after set", pm.isEmpty() == false);
    }

    // JumpTable
    {
        PC::JumpTable jt;
        TEST("JumpTable default isEmpty", jt.isEmpty() == true);
        TEST("JumpTable default cases empty", jt.getCases().empty());
        TEST("JumpTable default labels empty", jt.getLabelValues().empty());
        TEST("JumpTable default loads empty", jt.getLoadTables().empty());
        TEST("JumpTable default displayFormat 0", jt.getDisplayFormat() == 0);
        std::vector<Address> addrs{Address(ramSpace(), 0x100), Address(ramSpace(), 0x200)};
        PC::JumpTable jt2(Address(ramSpace(), 0x50), addrs, false, 1);
        TEST("JumpTable ctor non-empty", jt2.isEmpty() == false);
        TEST("JumpTable ctor 2 cases", jt2.getCases().size() == 2);
        TEST("JumpTable ctor displayFormat 1", jt2.getDisplayFormat() == 1);
    }

    // FunctionPrototype
    {
        PC::FunctionPrototype fp;
        TEST("FP default modelName", fp.getModelName() == "");
        TEST("FP default extrapop unknown", fp.getExtrapop() == PC::FunctionPrototype::UNKNOWN_EXTRAPOP);
        TEST("FP default isVarArg false", fp.isVarArg() == false);
        TEST("FP default isInline false", fp.isInline() == false);
        TEST("FP default isNoReturn false", fp.isNoReturn() == false);
        TEST("FP default isVoidInputLock false", fp.isVoidInputLock() == false);
        TEST("FP default isModelLock false", fp.isModelLock() == false);
        TEST("FP default isOutputLock false", fp.isOutputLock() == false);
        TEST("FP default numParams 0", fp.getNumParams() == 0);
        TEST("FP default hasCustomStorage false", fp.hasCustomStorage() == false);
        TEST("FP default hasThisPointer false", fp.hasThisPointer() == false);
        TEST("FP default getHighFunction null", fp.getHighFunction() == nullptr);
        TEST("FP default getLocalSymbolMap null", fp.getLocalSymbolMap() == nullptr);
        TEST("FP default getReturnType null", fp.getReturnType() == nullptr);
        TEST("FP default getReturnStorage null", fp.getReturnStorage() == nullptr);
        TEST("FP default getName empty", fp.getName() == "");

        fp.setName("foo");
        TEST("FP setName", fp.getName() == "foo");
        fp.setVarArg(true);
        TEST("FP setVarArg", fp.isVarArg() == true);
        fp.setInline(true);
        TEST("FP setInline", fp.isInline() == true);
        fp.setNoReturn(true);
        TEST("FP setNoReturn", fp.isNoReturn() == true);
        fp.setModelLock(true);
        TEST("FP setModelLock", fp.isModelLock() == true);
        fp.setVoidInputLock(true);
        TEST("FP setVoidInputLock", fp.isVoidInputLock() == true);
        fp.setOutputLock(true);
        TEST("FP setOutputLock", fp.isOutputLock() == true);
        fp.setCustomStorage(true);
        TEST("FP setCustomStorage", fp.hasCustomStorage() == true);
        fp.setThisPointer(true);
        TEST("FP setThisPointer", fp.hasThisPointer() == true);
        fp.setExtrapop(8);
        TEST("FP setExtrapop", fp.getExtrapop() == 8);
        fp.setConstruct(true);
        TEST("FP setConstruct", fp.isConstruct() == true);
        fp.setDestruct(true);
        TEST("FP setDestruct", fp.isDestruct() == true);
        fp.setReturnStorage(const_cast<Address*>(&Address::NO_ADDRESS));
        TEST("FP setReturnStorage", fp.getReturnStorage() != nullptr);
    }

    // HighFunctionDBUtil
    {
        std::string m = PC::HighFunctionDBUtil::getAutoModelName(nullptr, nullptr);
        TEST("HighFunctionDBUtil::getAutoModelName returns string", m == "__auto__");
        TEST("commitReturn is callable", (PC::HighFunctionDBUtil::commitReturn(nullptr, false), true));
        TEST("commitParams is callable", (PC::HighFunctionDBUtil::commitParams(nullptr, false), true));
        TEST("updateDBFunction is callable", (PC::HighFunctionDBUtil::updateDBFunction(nullptr, false), true));
        TEST("commitLocal returns false for null", PC::HighFunctionDBUtil::commitLocal(nullptr, nullptr, false) == false);
        TEST("convertHighParamToLocal false", PC::HighFunctionDBUtil::convertHighParamToLocal(nullptr, nullptr) == false);
        TEST("convertLocalToParam false", PC::HighFunctionDBUtil::convertLocalToParam(nullptr, 0, nullptr, false, false) == false);
        TEST("commitParam callable", (PC::HighFunctionDBUtil::commitParam(nullptr, false), true));
        TEST("findHighSymbol returns null", PC::HighFunctionDBUtil::findHighSymbol(nullptr, nullptr) == nullptr);
        TEST("isEquivalent returns false", PC::HighFunctionDBUtil::isEquivalent(nullptr, nullptr) == false);
        TEST("updateDBType callable", (PC::HighFunctionDBUtil::updateDBType("x", nullptr), true));
    }

    // VarnodeTranslator (with null language)
    {
        VarnodeTranslator vt((Language*)nullptr);
        TEST("VT null lang supportsPcode false", vt.supportsPcode() == false);
        TEST("VT getRegister null", vt.getRegister((Varnode*)nullptr) == nullptr);
        TEST("VT getVarnode null", vt.getVarnode((Register*)nullptr) == nullptr);
        TEST("VT getRegister(name) null", vt.getRegister("eax") == nullptr);
        TEST("VT getRegisters empty", vt.getRegisters().empty());
    }

    // PcodeOverride (interface — type recognized at compile time)
    {
        void* p = static_cast<PcodeOverride*>(nullptr);
        TEST("PcodeOverride type recognized", p == nullptr);
    }

    // Address::encode / decode roundtrip is not run (no real XML impl).
    // Just verify the static helpers are linkable.
    {
        Address a(ramSpace(), 0x1234);
        TEST("Address getOffset", a.getOffset() == 0x1234);
        TEST("Address getAddressSpace", a.getAddressSpace() == ramSpace());
    }

    // EquateTable per-(addr,opnd) tracking
    {
        EquateTableImpl eti;
        Address a(ramSpace(), 0x1000);
        Equate* e1 = eti.createEquate("MAGIC", 42, a, 1);
        TEST("EquateTable create with opnd", e1 != nullptr);
        Equate* e2 = eti.getEquate(a, 1, 42);
        TEST("EquateTable getEquate(addr,op,val)", e2 == e1);
        Equate* e3 = eti.getEquate(a, 1, 99);
        TEST("EquateTable getEquate wrong value null", e3 == nullptr);
        Equate* e4 = eti.getEquate(a, 2, 42);
        TEST("EquateTable getEquate wrong op null", e4 == nullptr);
        auto list = eti.getEquates(a, 1);
        TEST("EquateTable getEquates(addr,op) size 1", list.size() == 1);
        auto all = eti.getEquates(a);
        TEST("EquateTable getEquates(addr) size 1", all.size() == 1);
        eti.removeEquate(a, 1, 42);
        TEST("EquateTable getEquate after remove null", eti.getEquate(a, 1, 42) == nullptr);
        TEST("EquateTable getEquates after remove empty", eti.getEquates(a, 1).empty());

        // Multiple opnds at same address
        Address b(ramSpace(), 0x2000);
        eti.createEquate("ONE", 1, b, 0);
        eti.createEquate("TWO", 2, b, 1);
        eti.createEquate("THREE", 3, b, 2);
        auto allb = eti.getEquates(b);
        TEST("EquateTable getEquates(b) size 3", allb.size() == 3);
        eti.removeEquate(b, 1, 2);
        auto allb2 = eti.getEquates(b);
        TEST("EquateTable after remove one size 2", allb2.size() == 2);
    }

    std::cout << "\n=== " << passed << "/" << total << " tests passed ===\n";
    return (passed == total) ? 0 : 1;
}
