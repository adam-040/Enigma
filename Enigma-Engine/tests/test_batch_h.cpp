/**
 * Enigma Engine - Batch H (PcodeFactory + PcodeDataTypeManager interfaces) Test
 * Smoke tests for the PcodeFactory interface implemented by PcodeSyntaxTree
 * and the PcodeDataTypeManager metatype helpers + constants.
 */
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/PcodeSyntaxTree.h>
#include <ghidra/PcodeFactory.h>
#include <ghidra/PcodeDataTypeManager.h>
#include <ghidra/Metatype.h>
#include <ghidra/HighSymbol.h>
#include <ghidra/SequenceNumber.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/DefaultAddressFactory.h>
#include <iostream>
#include <cstring>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Batch H (PcodeFactory + PcodeDataTypeManager) Test ===\n";

    // ---------- PcodeDataTypeManager constants ----------
    TEST("PDT TYPE_VOID=14",   PcodeDataTypeManager::TYPE_VOID    == 14);
    TEST("PDT TYPE_UNKNOWN=12",PcodeDataTypeManager::TYPE_UNKNOWN == 12);
    TEST("PDT TYPE_INT=11",    PcodeDataTypeManager::TYPE_INT     == 11);
    TEST("PDT TYPE_UINT=10",   PcodeDataTypeManager::TYPE_UINT    == 10);
    TEST("PDT TYPE_BOOL=9",    PcodeDataTypeManager::TYPE_BOOL    == 9);
    TEST("PDT TYPE_CODE=8",    PcodeDataTypeManager::TYPE_CODE    == 8);
    TEST("PDT TYPE_FLOAT=7",   PcodeDataTypeManager::TYPE_FLOAT   == 7);
    TEST("PDT TYPE_PTR=6",     PcodeDataTypeManager::TYPE_PTR     == 6);
    TEST("PDT TYPE_PTRREL=5",  PcodeDataTypeManager::TYPE_PTRREL  == 5);
    TEST("PDT TYPE_ARRAY=4",   PcodeDataTypeManager::TYPE_ARRAY   == 4);
    TEST("PDT TYPE_STRUCT=3",  PcodeDataTypeManager::TYPE_STRUCT  == 3);
    TEST("PDT TYPE_UNION=2",   PcodeDataTypeManager::TYPE_UNION   == 2);

    // ---------- PcodeDataTypeManager::getMetatypeString ----------
    TEST("PDT str VOID",   PcodeDataTypeManager::getMetatypeString(14) == "void");
    TEST("PDT str UNKNOWN",PcodeDataTypeManager::getMetatypeString(12) == "unknown");
    TEST("PDT str INT",    PcodeDataTypeManager::getMetatypeString(11) == "int");
    TEST("PDT str UINT",   PcodeDataTypeManager::getMetatypeString(10) == "uint");
    TEST("PDT str BOOL",   PcodeDataTypeManager::getMetatypeString(9)  == "bool");
    TEST("PDT str CODE",   PcodeDataTypeManager::getMetatypeString(8)  == "code");
    TEST("PDT str FLOAT",  PcodeDataTypeManager::getMetatypeString(7)  == "float");
    TEST("PDT str PTR",    PcodeDataTypeManager::getMetatypeString(6)  == "ptr");
    TEST("PDT str PTRREL", PcodeDataTypeManager::getMetatypeString(5)  == "ptrrel");
    TEST("PDT str ARRAY",  PcodeDataTypeManager::getMetatypeString(4)  == "array");
    TEST("PDT str STRUCT", PcodeDataTypeManager::getMetatypeString(3)  == "struct");
    TEST("PDT str UNION",  PcodeDataTypeManager::getMetatypeString(2)  == "union");
    TEST("PDT str invalid",PcodeDataTypeManager::getMetatypeString(99) == "unknown");

    // ---------- PcodeDataTypeManager::getMetatypeFromString ----------
    TEST("PDT from void",   PcodeDataTypeManager::getMetatypeFromString("void")    == 14);
    TEST("PDT from unknown",PcodeDataTypeManager::getMetatypeFromString("unknown") == 12);
    TEST("PDT from int",    PcodeDataTypeManager::getMetatypeFromString("int")     == 11);
    TEST("PDT from uint",   PcodeDataTypeManager::getMetatypeFromString("uint")    == 10);
    TEST("PDT from bool",   PcodeDataTypeManager::getMetatypeFromString("bool")    == 9);
    TEST("PDT from code",   PcodeDataTypeManager::getMetatypeFromString("code")    == 8);
    TEST("PDT from float",  PcodeDataTypeManager::getMetatypeFromString("float")   == 7);
    TEST("PDT from ptr",    PcodeDataTypeManager::getMetatypeFromString("ptr")     == 6);
    TEST("PDT from ptrrel", PcodeDataTypeManager::getMetatypeFromString("ptrrel")  == 5);
    TEST("PDT from array",  PcodeDataTypeManager::getMetatypeFromString("array")   == 4);
    TEST("PDT from struct", PcodeDataTypeManager::getMetatypeFromString("struct")  == 3);
    TEST("PDT from union",  PcodeDataTypeManager::getMetatypeFromString("union")   == 2);
    TEST("PDT from garbage",PcodeDataTypeManager::getMetatypeFromString("xyzzy")   == 12);

    // ---------- PcodeDataTypeManager instance ----------
    PcodeDataTypeManager pdtm;
    TEST("PDT no program", pdtm.getProgram() == nullptr);
    TEST("PDT no transformer", pdtm.getNameTransformer() == nullptr);
    pdtm.setNameTransformer(nullptr);
    TEST("PDT setTransformer no-op", pdtm.getNameTransformer() == nullptr);
    TEST("PDT findBaseType null", pdtm.findBaseType("int", 0) == nullptr);
    TEST("PDT findDataType null", pdtm.findDataType(1) == nullptr);
    TEST("PDT resolveDataType null", pdtm.resolveDataType("foo", 0) == nullptr);
    TEST("PDT getPointerWordSize stub", pdtm.getPointerWordSize() == 0);

    // ---------- PcodeSyntaxTree implements PcodeFactory ----------
    GenericAddressSpace ramSpace("ram", 32, AddressSpace::TYPE_RAM, 0);
    GenericAddressSpace constSpace("const", 32, AddressSpace::TYPE_CONSTANT, 1);
    Address pcAddr(&ramSpace, 0x1000);
    Address dataAddr(&ramSpace, 0x2000);

    DefaultAddressFactory addrFact;
    PcodeSyntaxTree st(&addrFact);
    PcodeFactory* factory = &st;

    TEST("PST is PcodeFactory", factory != nullptr);
    TEST("PST getAddressFactory", factory->getAddressFactory() == &addrFact);
    TEST("PST getDataTypeManager no install", factory->getDataTypeManager() == nullptr);

    PcodeDataTypeManager mgr;
    st.setDataTypeManager(&mgr);
    TEST("PST getDataTypeManager installed", factory->getDataTypeManager() == &mgr);

    // newVarnode + refmap
    Varnode* v0 = factory->newVarnode(4, dataAddr, 999);
    TEST("PST newVarnode with id", v0 != nullptr && v0->getSize() == 4);
    TEST("PST getRef 999", factory->getRef(999) == v0);
    TEST("PST getRef missing", factory->getRef(12345) == nullptr);

    // setInput promotes to a new Varnode
    Varnode* inputVN = factory->newVarnode(4, dataAddr, 1000);
    Varnode* promoted = factory->setInput(inputVN, true);
    TEST("PST setInput(true) promoted", promoted != nullptr && promoted->isInput());
    // Unmark - setInput(false) on input should make it free
    Varnode* demoted = factory->setInput(promoted, false);
    TEST("PST setInput(false) demoted", demoted != nullptr);

    // setAddrTied, setPersistent, setUnaffected, setMergeGroup
    Varnode* v1 = factory->newVarnode(4, dataAddr, 1001);
    factory->setAddrTied(v1, true);
    factory->setPersistent(v1, true);
    factory->setUnaffected(v1, true);
    factory->setMergeGroup(v1, (int16_t)7);
    TEST("PST setAddrTied", v1->isAddrTied());
    TEST("PST setPersistent", v1->isPersistent());
    TEST("PST setUnaffected", v1->isUnaffected());
    TEST("PST setMergeGroup",
         static_cast<VarnodeAST*>(v1)->getMergeGroup() == 7);

    // setVolatile + setDataType (PcodeFactory additions)
    Varnode* v2 = factory->newVarnode(4, dataAddr, 1002);
    TEST("PST initial volatile false", !v2->isVolatile());
    TEST("PST initial datatype null", v2->getDataType() == nullptr);
    factory->setVolatile(v2, true);
    TEST("PST setVolatile", v2->isVolatile());
    factory->setDataType(v2, reinterpret_cast<DataType*>(0xdeadbeef));
    TEST("PST setDataType", v2->getDataType() == reinterpret_cast<DataType*>(0xdeadbeef));

    // newOp + getOpRef
    SequenceNumber sq(pcAddr, 42);
    Varnode* outVN = factory->newVarnode(4, dataAddr, 2000);
    std::vector<Varnode*> inputs;
    PcodeOp* op = factory->newOp(sq, PcodeOp::COPY, inputs, outVN);
    TEST("PST newOp", op != nullptr);
    TEST("PST getOpRef 42", factory->getOpRef(42) == op);
    TEST("PST getOpRef missing", factory->getOpRef(99999) == nullptr);

    // getSymbol stub returns nullptr
    TEST("PST getSymbol null", factory->getSymbol(1) == nullptr);

    // getJoinAddress with nullptr returns invalid Address
    Address joinAddr = factory->getJoinAddress(nullptr);
    TEST("PST getJoinAddress(null) invalid", !joinAddr.isValid() || joinAddr.getOffset() == 0);

    // getJoinStorage / buildStorage stubs return nullptr
    std::vector<Varnode*> pieces;
    TEST("PST getJoinStorage null", factory->getJoinStorage(pieces) == nullptr);
    TEST("PST buildStorage null", factory->buildStorage(v0) == nullptr);

    // ---------- HighSymbol stub ----------
    {
        class TestHighSymbol : public HighSymbol {
        public:
            int64_t id;
            std::string name;
            DataType* dt;
            int sz;
            Address addr;
            TestHighSymbol(int64_t i, const std::string& n, DataType* d, int s, const Address& a)
                : id(i), name(n), dt(d), sz(s), addr(a) {}
            int64_t getId() const override { return id; }
            const std::string& getName() const override { return name; }
            DataType* getDataType() const override { return dt; }
            int getSize() const override { return sz; }
            const Address& getStorageAddress() const override { return addr; }
        };
        TestHighSymbol sym(99, "x", nullptr, 4, dataAddr);
        TEST("HS getId", sym.getId() == 99);
        TEST("HS getName", sym.getName() == "x");
        TEST("HS getSize", sym.getSize() == 4);
        TEST("HS getDataType null", sym.getDataType() == nullptr);
        TEST("HS getStorageAddress", sym.getStorageAddress() == dataAddr);
    }

    std::cout << "=== Batch H: " << passed << "/" << total << " subtests passed ===\n";
    return (passed == total) ? 0 : 1;
}
