#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/ProgramAddressFactory.h"

#include "ghidra/Memory.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/FunctionManager.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

static int passed = 0, total = 0;
using namespace ghidra;
#define TEST(n, x)                                                                          \
    do {                                                                                    \
        total++;                                                                             \
        if (x) {                                                                             \
            std::cout << "[PASS] " << n << "\n" << std::flush;                               \
            passed++;                                                                        \
        } else {                                                                             \
            std::cout << "[FAIL] " << n << "\n" << std::flush;                               \
        }                                                                                    \
    } while (0)

static void putU16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}
static void putU32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}
static void putU64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}
static void putStr8(std::vector<uint8_t>& b, size_t off, const char* s) {
    std::memcpy(b.data() + off, s, std::min<size_t>(8, std::strlen(s)));
}

// Synthetic x64 COFF object:
// .text (exec, ADDR64 -> _g_data + REL32 -> _func1), .data (ADDR64 -> _func1),
// .bss. Symbols include section records with auxiliaries to exercise skipping.
static std::vector<uint8_t> buildCoffX64() {
    std::vector<uint8_t> b(0x800, 0);
    putU16(b, 0x00, 0x8664);   // machine AMD64
    putU16(b, 0x02, 3);        // NumberOfSections
    putU32(b, 0x04, 0);        // TimeDateStamp
    putU32(b, 0x08, 0x200);    // PointerToSymbolTable
    putU32(b, 0x0C, 7);        // NumberOfSymbols (4 real + 2 aux + 1)
    putU16(b, 0x10, 0);        // SizeOfOptionalHeader
    putU16(b, 0x12, 0);        // Characteristics

    // Section headers at 0x14
    // .text
    putStr8(b, 0x14, ".text");
    putU32(b, 0x1C, 16);        // VirtualSize
    putU32(b, 0x20, 0);         // VirtualAddress
    putU32(b, 0x24, 16);        // SizeOfRawData
    putU32(b, 0x28, 0x100);     // PointerToRawData
    putU32(b, 0x2C, 0x180);     // PointerToRelocations
    putU16(b, 0x34, 2);         // NumberOfRelocations
    putU32(b, 0x38, 0x60000020);// chars: CODE|EXEC|READ
    // .data
    putStr8(b, 0x3C, ".data");
    putU32(b, 0x44, 8);
    putU32(b, 0x48, 0);
    putU32(b, 0x4C, 8);
    putU32(b, 0x50, 0x120);
    putU32(b, 0x54, 0x1A0);
    putU16(b, 0x5C, 1);
    putU32(b, 0x60, 0xC0000040);// chars: DATA|READ|WRITE
    // .bss
    putStr8(b, 0x64, ".bss");
    putU32(b, 0x6C, 16);
    putU32(b, 0x70, 0);
    putU32(b, 0x74, 0);         // SizeOfRawData 0 (uninitialized)
    putU32(b, 0x78, 0);
    putU16(b, 0x84, 0);
    putU32(b, 0x88, 0xC0000080);// chars: UNINITIALIZED_DATA|READ|WRITE

    // .text raw data at 0x100: mov rax,[rip] placeholder + call rel32
    b[0x100] = 0x48; b[0x101] = 0x8B; b[0x102] = 0x05;
    putU32(b, 0x103, 0);
    b[0x10C] = 0xE8;
    putU32(b, 0x10D, 0);

    // Symbol table at 0x200 (18-byte entries; auxiliaries occupy table slots)
    // entry 0: .text SECTION (1 aux)
    putStr8(b, 0x200, ".text");
    putU16(b, 0x20C, 1);            // SectionNumber 1
    putU16(b, 0x20E, 0);            // Type
    b[0x210] = 3;                   // StorageClass SECTION
    b[0x211] = 1;                   // NumberOfAuxSymbols
    // entry 2: .data SECTION (1 aux)
    putStr8(b, 0x224, ".data");
    putU16(b, 0x230, 2);
    putU16(b, 0x232, 0);
    b[0x234] = 3;
    b[0x235] = 1;
    // entry 4: _func1 EXTERNAL FUNC in .text @ 0x10
    putStr8(b, 0x248, "_func1");
    putU32(b, 0x250, 0x10);         // Value (offset in .text)
    putU16(b, 0x254, 1);            // SectionNumber 1
    putU16(b, 0x256, 0x20);         // Type FUNC
    b[0x258] = 2;                   // StorageClass EXTERNAL
    // entry 5: _g_data EXTERNAL in .data @ 0
    putStr8(b, 0x25A, "_g_data");
    putU32(b, 0x262, 0);
    putU16(b, 0x266, 2);
    putU16(b, 0x268, 0);
    b[0x26A] = 2;
    // entry 6: _printf EXTERNAL undefined
    putStr8(b, 0x26C, "_printf");
    putU32(b, 0x274, 0);
    putU16(b, 0x278, 0);            // SectionNumber 0 (undefined)
    putU16(b, 0x27A, 0);
    b[0x27C] = 2;
    // String table (empty) at 0x200 + 7*18 = 0x27E
    putU32(b, 0x27E, 4);

    // Relocations: .text at 0x180 (ADDR64 @2 -> sym 5, REL32 @0xD -> sym 4)
    putU32(b, 0x180, 2);
    putU32(b, 0x184, 5);
    putU16(b, 0x188, 0x0001);
    putU32(b, 0x18A, 0xD);
    putU32(b, 0x18E, 4);
    putU16(b, 0x192, 0x0004);
    // .data at 0x1A0 (ADDR64 @0 -> sym 4)
    putU32(b, 0x1A0, 0);
    putU32(b, 0x1A4, 4);
    putU16(b, 0x1A8, 0x0001);

    return b;
}

// Synthetic ARM64 COFF object: .text (BRANCH26 -> _func1, ADDR32 -> _g_data),
// .data (ADDR64 -> _func1).
static std::vector<uint8_t> buildCoffArm64() {
    std::vector<uint8_t> b(0x800, 0);
    putU16(b, 0x00, 0xAA64);   // machine ARM64
    putU16(b, 0x02, 2);
    putU32(b, 0x08, 0x200);
    putU32(b, 0x0C, 6);        // 2 section syms + 2 aux + 2 real
    putU16(b, 0x10, 0);

    // .text
    putStr8(b, 0x14, ".text");
    putU32(b, 0x1C, 16);
    putU32(b, 0x20, 0);
    putU32(b, 0x24, 16);
    putU32(b, 0x28, 0x100);
    putU32(b, 0x2C, 0x180);
    putU16(b, 0x34, 2);
    putU32(b, 0x38, 0x60000020);
    // .data
    putStr8(b, 0x3C, ".data");
    putU32(b, 0x44, 8);
    putU32(b, 0x48, 0);
    putU32(b, 0x4C, 8);
    putU32(b, 0x50, 0x120);
    putU32(b, 0x54, 0x1A0);
    putU16(b, 0x5C, 1);
    putU32(b, 0x60, 0xC0000040);

    // .text raw: b #0 (imm26=0) at 0, then ADDR32 placeholder at 4
    putU32(b, 0x100, 0x14000000);
    putU32(b, 0x104, 0);

    // Symbol table (auxiliaries occupy table slots)
    // entry 0: .text SECTION (1 aux)
    putStr8(b, 0x200, ".text");
    putU16(b, 0x20C, 1);
    putU16(b, 0x20E, 0);
    b[0x210] = 3;
    b[0x211] = 1;
    // entry 2: .data SECTION (1 aux)
    putStr8(b, 0x224, ".data");
    putU16(b, 0x230, 2);
    putU16(b, 0x232, 0);
    b[0x234] = 3;
    b[0x235] = 1;
    // entry 4: _func1 EXTERNAL FUNC in .text @ 8
    putStr8(b, 0x248, "_func1");
    putU32(b, 0x250, 8);
    putU16(b, 0x254, 1);
    putU16(b, 0x256, 0x20);
    b[0x258] = 2;
    // entry 5: _g_data EXTERNAL in .data @ 0
    putStr8(b, 0x25A, "_g_data");
    putU32(b, 0x262, 0);
    putU16(b, 0x266, 2);
    putU16(b, 0x268, 0);
    b[0x26A] = 2;
    putU32(b, 0x26C, 4);      // empty string table at 0x200 + 6*18

    // Relocations: .text BRANCH26 @0 -> sym 4, ADDR32 @4 -> sym 5
    putU32(b, 0x180, 0);
    putU32(b, 0x184, 4);
    putU16(b, 0x188, 0x0003);
    putU32(b, 0x18A, 4);
    putU32(b, 0x18E, 5);
    putU16(b, 0x192, 0x0002);
    // .data ADDR64 @0 -> sym 4
    putU32(b, 0x1A0, 0);
    putU32(b, 0x1A4, 4);
    putU16(b, 0x1A8, 0x000E);

    return b;
}

// Minimal x64 COFF used as an archive member: one .text section, one defined
// external symbol (ADDR64 relocation @0), one undefined external.
static std::vector<uint8_t> buildSimpleX64Obj(const char* tag) {
    std::vector<uint8_t> b(0x300, 0);
    putU16(b, 0x00, 0x8664);
    putU16(b, 0x02, 1);
    putU32(b, 0x08, 0x100);   // PointerToSymbolTable
    putU32(b, 0x0C, 4);       // .text SECTION + aux + 2 real
    putU16(b, 0x10, 0);

    putStr8(b, 0x14, ".text");
    putU32(b, 0x1C, 8);
    putU32(b, 0x20, 0);
    putU32(b, 0x24, 8);
    putU32(b, 0x28, 0x40);    // PointerToRawData
    putU32(b, 0x2C, 0x150);   // PointerToRelocations
    putU16(b, 0x34, 1);
    putU32(b, 0x3C, 0x60000020);

    // Symbol table at 0x100
    putStr8(b, 0x100, ".text");
    putU16(b, 0x10C, 1);
    b[0x110] = 3;             // SECTION
    b[0x111] = 1;             // 1 aux entry

    char sym1[9] = "_a_data", sym2[9] = "_a_ext";
    sym1[1] = tag[0]; sym2[1] = tag[0];
    putStr8(b, 0x124, sym1);
    putU32(b, 0x12C, 4);
    putU16(b, 0x130, 1);      // section 1
    b[0x134] = 2;             // EXTERNAL
    putStr8(b, 0x136, sym2);
    putU32(b, 0x13E, 0);
    putU16(b, 0x142, 0);      // undefined
    b[0x146] = 2;

    putU32(b, 0x148, 4);      // empty string table

    putU32(b, 0x150, 0);      // reloc: r_offset 0
    putU32(b, 0x154, 2);      // sym index 2 = _x_data
    putU16(b, 0x158, 0x0001); // ADDR64

    return b;
}

static void putArchHeader(std::vector<uint8_t>& b, size_t off, const std::string& name,
                          size_t size) {
    std::string n = name + "/";
    n.resize(16, ' ');
    std::memcpy(b.data() + off, n.data(), 16);
    std::string ts = "0          "; // 12
    std::memcpy(b.data() + off + 16, ts.data(), 12);
    std::string uid = "0     ";
    std::memcpy(b.data() + off + 28, uid.data(), 6);
    std::memcpy(b.data() + off + 34, uid.data(), 6);
    std::string mode = "100644  ";
    std::memcpy(b.data() + off + 40, mode.data(), 8);
    char sz[11] = {};
    std::snprintf(sz, 11, "%10zu", size);
    std::memcpy(b.data() + off + 48, sz, 10);
    b[off + 58] = '`';
    b[off + 59] = '\n';
}

// COFF archive (.lib) with two members.
static std::vector<uint8_t> buildCoffLib() {
    std::vector<uint8_t> a = buildSimpleX64Obj("a");
    std::vector<uint8_t> c = buildSimpleX64Obj("b");
    size_t total = 8 + 60 + a.size() + (a.size() & 1) + 60 + c.size() + (c.size() & 1);
    std::vector<uint8_t> b(total, '\n');
    std::memcpy(b.data(), "!<arch>\n", 8);
    size_t pos = 8;
    putArchHeader(b, pos, "a.obj", a.size());
    pos += 60;
    std::memcpy(b.data() + pos, a.data(), a.size());
    pos += a.size() + (a.size() & 1);
    putArchHeader(b, pos, "b.obj", c.size());
    pos += 60;
    std::memcpy(b.data() + pos, c.data(), c.size());
    return b;
}

static std::vector<std::pair<std::string, uint64_t>> importSet(BinaryLoader* l) {
    std::vector<std::pair<std::string, uint64_t>> v;
    for (const auto& imp : l->getImports()) {
        v.emplace_back(imp.functionName, imp.address);
    }
    std::sort(v.begin(), v.end());
    return v;
}

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
          prog("coff_loader_test", nullptr, nullptr) {
        auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(prog.getAddressFactory());
        if (addrFactory) {
            addrFactory->addAddressSpace(&ramSpace);
            addrFactory->setDefaultSpace(&ramSpace);
            addrFactory->setConstantSpace(&constSpace);
            addrFactory->setUniqueSpace(&uniqueSpace);
            addrFactory->setRegisterSpace(&registerSpace);
            addrFactory->setStackSpace(&stackSpace);
        }
    }

    Address ram(uint64_t off) {
        return Address(&ramSpace, static_cast<int64_t>(off));
    }
};

int main() {
    const std::string p1 = "test_coff_x64.obj";
    {
        std::ofstream out(p1, std::ios::binary);
        std::vector<uint8_t> bytes = buildCoffX64();
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    auto l64 = createLoader();
    TEST("x64 obj loads", l64->load(p1));
    TEST("x64 obj format", l64->getFormatName() == "COFF");
    TEST("x64 obj arch", l64->getArchitecture() == "x86" && l64->getBitness() == 64);
    {
        auto secs = l64->getSections();
        TEST("x64 obj sections", secs.size() == 3 && secs[0].name == ".text" &&
             secs[1].name == ".data" && secs[2].name == ".bss");
        TEST("x64 obj layout", secs[0].virtualAddress == 0 &&
             secs[1].virtualAddress == 0x1000 && secs[2].virtualAddress == 0x2000);
        TEST("x64 obj flags", secs[0].isExecutable && !secs[0].isWritable &&
             secs[1].isWritable && secs[2].isWritable && !secs[2].isExecutable);
    }
    {
        bool f1 = false, gd = false;
        for (const auto& s : l64->getSymbols()) {
            if (s.name == "_func1") f1 = s.address == 0x10 && s.isFunction;
            if (s.name == "_g_data") gd = s.address == 0x1000 && !s.isFunction;
        }
        TEST("x64 obj symbols", f1 && gd);
    }
    {
        std::vector<std::pair<std::string, uint64_t>> expect = {{"_printf", 0}};
        TEST("x64 obj imports", importSet(l64.get()) == expect);
    }
    {
        std::vector<uint8_t> bytes = l64->getRawDataCopy();
        uint64_t addr64 = 0;
        for (int i = 0; i < 8; ++i) addr64 |= static_cast<uint64_t>(bytes[0x102 + i]) << (8 * i);
        uint32_t rel32 = 0;
        for (int i = 0; i < 4; ++i) rel32 |= static_cast<uint32_t>(bytes[0x10D + i]) << (8 * i);
        TEST("x64 ADDR64 patched", addr64 == 0x1000);
        TEST("x64 REL32 patched", rel32 == 0xFFFFFFFF); // 0x10 - (0xD + 4)
        uint64_t dataPtr = 0;
        for (int i = 0; i < 8; ++i) dataPtr |= static_cast<uint64_t>(bytes[0x120 + i]) << (8 * i);
        TEST("x64 .data ADDR64 patched", dataPtr == 0x10);
    }

    TestProgram tprog;
    TEST("x64 obj populateProgram", l64->populateProgram(&tprog.prog));
    {
        Memory* mem = tprog.prog.getMemory();
        TEST("x64 block at text", mem && mem->getBlock(tprog.ram(0)) != nullptr);
        TEST("x64 block at bss", mem && mem->getBlock(tprog.ram(0x2000)) != nullptr);
        SymbolTable* st = tprog.prog.getSymbolTable();
        TEST("x64 label at g_data", st->hasSymbol(tprog.ram(0x1000)));
        TEST("x64 function at func1",
             tprog.prog.getFunctionManager()->getFunctionAt(tprog.ram(0x10)) != nullptr);
    }

    const std::string p2 = "test_coff_arm64.obj";
    {
        std::ofstream out(p2, std::ios::binary);
        std::vector<uint8_t> bytes = buildCoffArm64();
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    auto lArm = createLoader();
    TEST("arm64 obj loads", lArm->load(p2));
    TEST("arm64 obj format", lArm->getFormatName() == "COFF");
    TEST("arm64 obj arch", lArm->getArchitecture() == "AARCH64" && lArm->getBitness() == 64);
    {
        auto secs = lArm->getSections();
        TEST("arm64 obj sections", secs.size() == 2 && secs[0].virtualAddress == 0 &&
             secs[1].virtualAddress == 0x1000);
    }
    {
        bool f1 = false, gd = false;
        for (const auto& s : lArm->getSymbols()) {
            if (s.name == "_func1") f1 = s.address == 8 && s.isFunction;
            if (s.name == "_g_data") gd = s.address == 0x1000;
        }
        TEST("arm64 obj symbols", f1 && gd);
    }
    {
        std::vector<uint8_t> bytes = lArm->getRawDataCopy();
        uint32_t br = 0, addr32 = 0;
        for (int i = 0; i < 4; ++i) {
            br |= static_cast<uint32_t>(bytes[0x100 + i]) << (8 * i);
            addr32 |= static_cast<uint32_t>(bytes[0x104 + i]) << (8 * i);
        }
        uint64_t addr64 = 0;
        for (int i = 0; i < 8; ++i) addr64 |= static_cast<uint64_t>(bytes[0x120 + i]) << (8 * i);
        TEST("arm64 BRANCH26 patched", br == 0x14000002); // imm26 = (8-0)>>2
        TEST("arm64 ADDR32 patched", addr32 == 0x1000);
        TEST("arm64 ADDR64 patched", addr64 == 8);
    }

    const std::string p3 = "test_coff.lib";
    {
        std::ofstream out(p3, std::ios::binary);
        std::vector<uint8_t> bytes = buildCoffLib();
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    auto lLib = createLoader();
    TEST("coff lib loads", lLib->load(p3));
    TEST("coff lib format", lLib->getFormatName() == "COFF Archive");
    TEST("coff lib arch", lLib->getArchitecture() == "x86" && lLib->getBitness() == 64);
    {
        auto secs = lLib->getSections();
        TEST("coff lib sections", secs.size() == 2 &&
             secs[0].name == "a.obj_.text" && secs[1].name == "b.obj_.text" &&
             secs[0].virtualAddress == 0 && secs[1].virtualAddress == 0x1000);
    }
    {
        bool da = false, db = false;
        for (const auto& s : lLib->getSymbols()) {
            if (s.name == "_a_data") da = s.address == 4;
            if (s.name == "_b_data") db = s.address == 0x1004;
        }
        TEST("coff lib symbols", da && db);
    }
    {
        std::vector<std::pair<std::string, uint64_t>> expect = {{"_a_ext", 0}, {"_b_ext", 0}};
        std::sort(expect.begin(), expect.end());
        TEST("coff lib imports", importSet(lLib.get()) == expect);
    }
    {
        std::vector<uint8_t> bytes = lLib->getRawDataCopy();
        size_t memA = 8 + 60;                        // first member data
        size_t memB = memA + 0x300 + (0x300 & 1) + 60;
        uint64_t pa = 0, pb = 0;
        for (int i = 0; i < 8; ++i) {
            pa |= static_cast<uint64_t>(bytes[memA + 0x40 + i]) << (8 * i);
            pb |= static_cast<uint64_t>(bytes[memB + 0x40 + i]) << (8 * i);
        }
        TEST("coff lib member patches", pa == 4 && pb == 0x1004);
    }

    std::remove(p1.c_str());
    std::remove(p2.c_str());
    std::remove(p3.c_str());
    std::cout << "COFF Loader Tests: " << passed << "/" << total << " passed.\n" << std::flush;
    return (passed == total) ? 0 : 1;
}