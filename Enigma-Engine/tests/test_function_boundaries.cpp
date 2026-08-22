/**
 * Enigma Engine - Function Entry Boundary Trimming Test
 * Validates Task 1.4: FunctionStartAnalyzer must not leave function entries
 * anchored on NOP/INT3 alignment padding. Covers:
 *   - MOVE: entry on padding with real code after -> trimmed forward, name kept
 *   - DROP (owned): entry on padding whose real start is another function
 *   - DROP (block end): entry on padding run extending to the block boundary
 *   - UNTOUCHED: real entry preceded by padding is never moved
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

#include "ghidra/FunctionStartAnalyzer.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/Memory.h"
#include "ghidra/TaskMonitor.h"
#include "ghidra/MessageLog.h"
#include "ghidra/Language.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/Function.h"
#include "ghidra/AddressSet.h"
#include "ghidra/AutoNaming.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

struct TestProgram {
    GenericAddressSpace ramSpace;
    GenericAddressSpace constSpace;
    GenericAddressSpace uniqueSpace;
    GenericAddressSpace registerSpace;
    GenericAddressSpace stackSpace;
    ProgramDB prog;

    TestProgram()
        : ramSpace("ram", 64, AddressSpace::TYPE_RAM, 1),
          constSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2),
          uniqueSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3),
          registerSpace("register", 64, AddressSpace::TYPE_REGISTER, 4),
          stackSpace("stack", 64, AddressSpace::TYPE_STACK, 5),
          prog("function_boundaries_test", nullptr, nullptr) {
        auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(prog.getAddressFactory());
        if (addrFactory) {
            addrFactory->addAddressSpace(&ramSpace);
            addrFactory->setDefaultSpace(&ramSpace);
            addrFactory->setConstantSpace(&constSpace);
            addrFactory->setUniqueSpace(&uniqueSpace);
            addrFactory->setRegisterSpace(&registerSpace);
            addrFactory->setStackSpace(&stackSpace);
        }
        prog.setLanguageID(LanguageID("x86:LE:64:default"));
    }

    Address addr(uint64_t off) {
        return Address(&ramSpace, static_cast<int64_t>(off));
    }
};

static std::vector<uint8_t> buildBlock() {
    std::vector<uint8_t> b(0xC0, 0xCC);
    // 0x1000: call rel32 -> 0x1058 (Case A: padding + real non-pattern code)
    b[0x000] = 0xE8; b[0x001] = 0x53; b[0x002] = 0x00; b[0x003] = 0x00; b[0x004] = 0x00;
    // 0x1005: call rel32 -> 0x10A0 (Case B: padding run to block end)
    b[0x005] = 0xE8; b[0x006] = 0x96; b[0x007] = 0x00; b[0x008] = 0x00; b[0x009] = 0x00;
    // 0x100A: call rel32 -> 0x1030 (Case C: padding + pattern prologue)
    b[0x00A] = 0xE8; b[0x00B] = 0x21; b[0x00C] = 0x00; b[0x00D] = 0x00; b[0x00E] = 0x00;
    // 0x1030: 90 90 90 55 48 89 E5 C3   (padding then push rbp; mov rbp,rsp; ret)
    b[0x030] = 0x90; b[0x031] = 0x90; b[0x032] = 0x90;
    b[0x033] = 0x55; b[0x034] = 0x48; b[0x035] = 0x89; b[0x036] = 0xE5; b[0x037] = 0xC3;
    // 0x1058: 90 90 4C 89 44 24 08 C3   (padding then mov [rsp+8],r8; ret)
    b[0x058] = 0x90; b[0x059] = 0x90;
    b[0x05A] = 0x4C; b[0x05B] = 0x89; b[0x05C] = 0x44; b[0x05D] = 0x24; b[0x05E] = 0x08; b[0x05F] = 0xC3;
    // 0x1090: 90 31 C0 C3               (padding then xor eax,eax; ret - real entry)
    b[0x090] = 0x90;
    b[0x091] = 0x31; b[0x092] = 0xC0; b[0x093] = 0xC3;
    // 0x10A0..0x10BF: NOP padding run to block end (Case B region)
    for (int i = 0xA0; i < 0xC0; ++i) b[i] = 0x90;
    return b;
}

static Function* findFunc(FunctionManager* fm, uint64_t off) {
    AddressSet all;
    FunctionIterator it = fm->getFunctions(true);
    while (it.hasNext()) {
        Function* f = it.next();
        if (f && f->getEntryPoint().getOffset() == static_cast<int64_t>(off)) return f;
    }
    return nullptr;
}

int main() {
    TestProgram tprog;
    Address startAddr = tprog.addr(0x1000);
    Memory* memory = tprog.prog.getMemory();
    std::vector<uint8_t> data = buildBlock();
    DefaultMemory* defaultMem = dynamic_cast<DefaultMemory*>(memory);
    TEST("memory is DefaultMemory", defaultMem != nullptr);
    DefaultMemoryBlock* block = defaultMem ? defaultMem->createInitializedBlock(".text", startAddr, data.size()) : nullptr;
    TEST("block created", block != nullptr);
    if (!block) {
        std::cout << "Function Boundary Tests: " << passed << "/" << total << " passed.\n";
        return 1;
    }
    block->setExecute(true);
    int written = block->putBytes(startAddr, data.data(), static_cast<int>(data.size()));
    TEST("block bytes written", written == static_cast<int>(data.size()));

    FunctionStartAnalyzer analyzer;
    TEST("canAnalyze", analyzer.canAnalyze(&tprog.prog));

    AddressSet set;
    StubTaskMonitor monitor;
    MessageLog log;
    bool ok = false;
    try {
        ok = analyzer.added(&tprog.prog, set, &monitor, log);
    } catch (const std::exception& e) {
        std::cerr << "added() threw: " << e.what() << "\n";
    }
    TEST("FunctionStartAnalyzer::added completes", ok);

    FunctionManager* fm = tprog.prog.getFunctionManager();

    // Case C: phantom at 0x1030 dropped (real entry 0x1033 already owned by func_0x1033)
    TEST("C: no function at 0x1030", fm->getFunctionAt(tprog.addr(0x1030)) == nullptr);
    Function* f1033 = findFunc(fm, 0x1033);
    TEST("C: function at 0x1033 kept", f1033 != nullptr);
    if (f1033) TEST("C: func_0x1033 name", f1033->getName() == "func_0x1033");

    // Case A: phantom at 0x1058 moved to 0x105A with name preserved
    TEST("A: no function at 0x1058", fm->getFunctionAt(tprog.addr(0x1058)) == nullptr);
    Function* f105a = findFunc(fm, 0x105A);
    TEST("A: function moved to 0x105A", f105a != nullptr);
    if (f105a) TEST("A: name preserved func_0x1058", f105a->getName() == "func_0x1058");

    // Case B: phantom at 0x10A0 dropped (padding to block end)
    TEST("B: no function at 0x10A0", fm->getFunctionAt(tprog.addr(0x10A0)) == nullptr);

    // Untouched: real entry at 0x1091 (xor eax,eax; ret) preceded by padding
    Function* f1091 = findFunc(fm, 0x1091);
    TEST("untouched: function at 0x1091 kept", f1091 != nullptr);
    if (f1091) TEST("untouched: func_0x1091 name", f1091->getName() == "func_0x1091");

    // Exactly three functions remain
    int count = 0;
    FunctionIterator it = fm->getFunctions(true);
    while (it.hasNext()) { it.next(); ++count; }
    TEST("total function count is 3", count == 3);

    std::cout << "Function Boundary Tests: " << passed << "/" << total << " passed.\n" << std::flush;
    return (passed == total) ? 0 : 1;
}