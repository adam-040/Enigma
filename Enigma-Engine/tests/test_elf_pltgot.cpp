/**
 * Enigma Engine - ELF Dynamic PLTGOT Recovery Test (GP-7056 / Task 2.2)
 * Section-header-stripped ELFs (e_shoff == 0) must still yield:
 *   - memory sections synthesized from PT_LOAD program headers;
 *   - named imports recovered from PT_DYNAMIC (DT_JMPREL/DT_RELA/DT_REL
 *     resolved via the dynamic symbol table), covering both GOT slots and
 *     PLT stubs (x86 FF 25 reverse scan, AARCH64/ARM pattern scans);
 *   - DT_NEEDED library records.
 * Verified on synthetic stripped ELF64 (RELA) + ELF32 (REL) fixtures and by
 * import-set equality between real corpus ELFs and their stripped copies.
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <cstring>
#include <algorithm>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/Memory.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

using namespace ghidra;

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
static void putStr(std::vector<uint8_t>& b, size_t off, const char* s) {
    std::memcpy(b.data() + off, s, std::strlen(s) + 1);
}

// GNU hash function (djb2 variant) for building DT_GNU_HASH.
static uint32_t gnuHash(const char* s) {
    uint32_t h = 5381;
    for (const uint8_t* p = reinterpret_cast<const uint8_t*>(s); *p; ++p) h = h * 33 + *p;
    return h;
}

// Synthetic stripped x86-64 ELF (ET_EXEC, RELA, e_shoff = 0).
// PH1: text R+X at 0x400000 (PLT0 + 2 stubs); PH2: data R+W at 0x401000
// (.dynamic, dynsym, dynstr, GNU hash, .rela.dyn, .rela.plt, GOT);
// PH3: PT_DYNAMIC. The GNU hash table (DT_GNU_HASH) carries a 5th dynsym
// entry ("my_func", a defined function referenced by NO relocation) so the
// hash-derived symbol count is observable: without it the table would be
// sized from the relocation indices only and my_func would be lost.
static std::vector<uint8_t> buildStrippedELF64() {
    std::vector<uint8_t> b(0x2400, 0);

    // ELF header (64 bytes)
    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2;                       // EI_CLASS: ELFCLASS64
    b[5] = 1;                       // EI_DATA: little endian
    putU16(b, 0x10, 2);             // e_type: ET_EXEC
    putU16(b, 0x12, 0x3E);          // e_machine: x86-64
    putU32(b, 0x14, 1);             // e_version
    putU64(b, 0x18, 0x400000);      // e_entry
    putU64(b, 0x20, 64);            // e_phoff
    putU16(b, 0x34, 64);            // e_ehsize
    putU16(b, 0x36, 56);            // e_phentsize
    putU16(b, 0x38, 3);             // e_phnum
    // e_shoff/e_shentsize/e_shnum stay 0: stripped.

    // Program headers (56 bytes each at 0x40)
    // PH1: PT_LOAD text
    putU32(b, 0x40, 1);             // PT_LOAD
    putU32(b, 0x44, 5);             // flags R+X
    putU64(b, 0x48, 0x1000);        // p_offset
    putU64(b, 0x50, 0x400000);      // p_vaddr
    putU64(b, 0x60, 0x200);         // p_filesz
    putU64(b, 0x68, 0x200);         // p_memsz
    putU64(b, 0x70, 0x1000);        // p_align
    // PH2: PT_LOAD data
    putU32(b, 0x78, 1);
    putU32(b, 0x7C, 6);             // flags R+W
    putU64(b, 0x80, 0x2000);
    putU64(b, 0x88, 0x401000);
    putU64(b, 0x98, 0x300);
    putU64(b, 0xA0, 0x300);
    putU64(b, 0xA8, 0x1000);
    // PH3: PT_DYNAMIC (inside PH2)
    putU32(b, 0xB0, 2);             // PT_DYNAMIC
    putU32(b, 0xB4, 6);
    putU64(b, 0xB8, 0x2000);
    putU64(b, 0xC0, 0x401000);
    putU64(b, 0xD0, 0xB0);          // p_filesz
    putU64(b, 0xD8, 0xB0);          // p_memsz
    putU64(b, 0xE0, 8);

    // .text at 0x1000 (vaddr 0x400000): PLT0 + 2 stubs (16-byte slots)
    // PLT0 at 0x400100: FF 35 disp (push [got+8]); FF 25 disp (jmp [got+16])
    b[0x1100] = 0xFF; b[0x1101] = 0x35;
    putU32(b, 0x1102, 0x401208 - 0x400106);   // -> 0x401208 (got+8)
    b[0x1106] = 0xFF; b[0x1107] = 0x25;
    putU32(b, 0x1108, 0x401210 - 0x40010C);   // -> 0x401210 (got+16)
    putU32(b, 0x110C, 0x00401F0F);            // nop dword [rax]
    // stub0 at 0x400110: jmp [rip+disp] -> 0x401230 (puts GOT slot)
    b[0x1110] = 0xFF; b[0x1111] = 0x25;
    putU32(b, 0x1112, 0x401230 - 0x400116);
    // stub1 at 0x400120: jmp [rip+disp] -> 0x401238 (printf GOT slot)
    b[0x1120] = 0xFF; b[0x1121] = 0x25;
    putU32(b, 0x1122, 0x401238 - 0x400126);

    // .dynamic at 0x2000 (vaddr 0x401000): 12 entries x 16 bytes
    size_t dyn = 0x2000;
    auto dynEnt = [&](size_t i, int64_t tag, uint64_t val) {
        size_t o = dyn + i * 16;
        putU64(b, o, static_cast<uint64_t>(tag));
        putU64(b, o + 8, val);
    };
    dynEnt(0, 1, 1);        // DT_NEEDED -> dynstr[1] = "libc.so.6"
    dynEnt(1, 2, 48);       // DT_PLTRELSZ: 2 x RELA
    dynEnt(2, 5, 0x401140); // DT_STRTAB
    dynEnt(3, 6, 0x4010C0); // DT_SYMTAB
    dynEnt(4, 11, 24);      // DT_SYMENT
    dynEnt(5, 7, 0x4011C0); // DT_RELA (.rela.dyn)
    dynEnt(6, 8, 24);       // DT_RELASZ
    dynEnt(7, 9, 24);       // DT_RELAENT
    dynEnt(8, 23, 0x4011D8);// DT_JMPREL (.rela.plt)
    dynEnt(9, 20, 7);       // DT_PLTREL: RELA
    dynEnt(10, 0x6FFFFEF5, 0x401170); // DT_GNU_HASH
    dynEnt(11, 0, 0);       // DT_NULL

    // dynsym at 0x20C0 (vaddr 0x4010C0): 5 x 24 bytes
    // [0] null, [1] puts, [2] printf, [3] _g_data, [4] my_func (defined)
    auto symEnt = [&](size_t i, uint32_t nameIdx, uint8_t info, uint16_t shndx) {
        size_t o = 0x20C0 + i * 24;
        putU32(b, o, nameIdx);
        b[o + 4] = info;
        putU16(b, o + 6, shndx);
    };
    symEnt(0, 0, 0, 0);
    symEnt(1, 12, 0x12, 0); // GLOBAL FUNC UND  ("puts")
    symEnt(2, 17, 0x12, 0); // GLOBAL FUNC UND  ("printf")
    symEnt(3, 24, 0x11, 0); // GLOBAL OBJECT UND ("_g_data")
    symEnt(4, 32, 0x12, 1); // GLOBAL FUNC defined @ 0x400180 ("my_func")
    putU64(b, 0x20C0 + 4 * 24 + 8, 0x400180);

    // dynstr at 0x2140 (vaddr 0x401140):
    // "\0libc.so.6\0puts\0printf\0_g_data\0my_func\0"
    putStr(b, 0x2141, "libc.so.6");
    putStr(b, 0x214C, "puts");
    putStr(b, 0x2151, "printf");
    putStr(b, 0x2158, "_g_data");
    putStr(b, 0x2160, "my_func");

    // GNU hash table at 0x2170 (vaddr 0x401170): header + bloom + buckets +
    // chains. symoffset 1: symbols 1..4 are bucketed, chain pos = idx - 1.
    const char* hnames[4] = {"puts", "printf", "_g_data", "my_func"};
    uint32_t hhashes[4];
    for (int i = 0; i < 4; ++i) hhashes[i] = gnuHash(hnames[i]);
    uint32_t nbuckets = 8;
    bool distinct = false;
    while (!distinct) {
        distinct = true;
        for (int i = 0; i < 4 && distinct; ++i)
            for (int j = i + 1; j < 4; ++j)
                if (hhashes[i] % nbuckets == hhashes[j] % nbuckets) distinct = false;
        if (!distinct) nbuckets *= 2;
    }
    putU32(b, 0x2170, nbuckets);
    putU32(b, 0x2174, 1);       // symoffset
    putU32(b, 0x2178, 1);       // bloom_size (words)
    putU32(b, 0x217C, 6);       // bloom_shift
    putU64(b, 0x2180, 0);       // bloom filter (count comes from buckets/chains)
    for (int i = 0; i < 4; ++i)
        putU32(b, 0x2188 + (hhashes[i] % nbuckets) * 4, static_cast<uint32_t>(i) + 1);
    for (int i = 0; i < 4; ++i)
        putU32(b, 0x2188 + nbuckets * 4 + i * 4, hhashes[i] | 1);

    // .rela.dyn at 0x21C0: GLOB_DAT _g_data -> 0x401240
    putU64(b, 0x21C0, 0x401240);            // r_offset
    putU64(b, 0x21C8, (3ULL << 32) | 6ULL); // r_info: sym 3, GLOB_DAT
    putU64(b, 0x21D0, 0);                   // r_addend

    // .rela.plt at 0x21D8: puts -> 0x401230, printf -> 0x401238
    putU64(b, 0x21D8, 0x401230);            // r_offset
    putU64(b, 0x21E0, (1ULL << 32) | 7ULL); // r_info: sym 1, JUMP_SLOT
    putU64(b, 0x21E8, 0);
    putU64(b, 0x21F0, 0x401238);
    putU64(b, 0x21F8, (2ULL << 32) | 7ULL);
    putU64(b, 0x2200, 0);

    // GOT at 0x2200 (vaddr 0x401200): [0],[1] reserved, [2] resolver, slots
    putU64(b, 0x2200, 0);
    putU64(b, 0x2208, 0);
    putU64(b, 0x2210, 0x400106);
    putU64(b, 0x2218, 0);   // puts slot (0x401230)
    putU64(b, 0x2220, 0);   // printf slot (0x401238)
    putU64(b, 0x2228, 0);   // _g_data slot (0x401240)

    return b;
}

// Synthetic stripped x86 ELF (ET_EXEC, REL, e_shoff = 0). One import: puts.
static std::vector<uint8_t> buildStrippedELF32() {
    std::vector<uint8_t> b(0x2200, 0);

    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 1;                       // ELFCLASS32
    b[5] = 1;                       // little endian
    putU16(b, 0x10, 2);             // ET_EXEC
    putU16(b, 0x12, 3);             // e_machine: i386
    putU32(b, 0x14, 1);
    putU32(b, 0x18, 0x400000);      // e_entry
    putU32(b, 0x1C, 52);            // e_phoff
    putU16(b, 0x28, 52);            // e_ehsize
    putU16(b, 0x2A, 32);            // e_phentsize
    putU16(b, 0x2C, 3);             // e_phnum

    // Program headers (32 bytes each at 0x34)
    // PH1: PT_LOAD text R+X
    putU32(b, 0x34, 1);
    putU32(b, 0x38, 0x1000);        // p_offset
    putU32(b, 0x3C, 0x400000);      // p_vaddr
    putU32(b, 0x40, 0x400000);      // p_paddr
    putU32(b, 0x44, 0x180);         // p_filesz
    putU32(b, 0x48, 0x180);         // p_memsz
    putU32(b, 0x4C, 5);             // p_flags R+X
    putU32(b, 0x50, 0x1000);        // p_align
    // PH2: PT_LOAD data R+W
    putU32(b, 0x54, 1);
    putU32(b, 0x58, 0x2000);
    putU32(b, 0x5C, 0x401000);
    putU32(b, 0x60, 0x401000);
    putU32(b, 0x64, 0x200);
    putU32(b, 0x68, 0x200);
    putU32(b, 0x6C, 6);
    putU32(b, 0x70, 0x1000);
    // PH3: PT_DYNAMIC
    putU32(b, 0x74, 2);
    putU32(b, 0x78, 0x2000);
    putU32(b, 0x7C, 0x401000);
    putU32(b, 0x80, 0x401000);
    putU32(b, 0x84, 0x40);
    putU32(b, 0x88, 0x40);
    putU32(b, 0x8C, 6);
    putU32(b, 0x90, 8);

    // .text at 0x1000: PLT0 at 0x400100, stub0 at 0x400110 (jmp [0x40110C])
    b[0x1100] = 0xFF; b[0x1101] = 0x35;
    putU32(b, 0x1102, 0x401108);      // push [0x401108]
    b[0x1106] = 0xFF; b[0x1107] = 0x25;
    putU32(b, 0x1108, 0x401108);      // jmp [0x401108] (resolver)
    putU32(b, 0x110C, 0x90909090);    // nops
    b[0x1110] = 0xFF; b[0x1111] = 0x25;
    putU32(b, 0x1112, 0x40110C);      // jmp [0x40110C]  <-- puts stub

    // .dynamic at 0x2000: 9 entries x 8 bytes
    size_t dyn = 0x2000;
    auto dynEnt = [&](size_t i, int32_t tag, uint32_t val) {
        size_t o = dyn + i * 8;
        putU32(b, o, static_cast<uint32_t>(tag));
        putU32(b, o + 4, val);
    };
    dynEnt(0, 1, 6);        // DT_NEEDED -> dynstr[6] = "libc.so.6"
    dynEnt(1, 2, 8);        // DT_PLTRELSZ: 1 x REL
    dynEnt(2, 5, 0x4010C0); // DT_STRTAB
    dynEnt(3, 6, 0x401080); // DT_SYMTAB
    dynEnt(4, 11, 16);      // DT_SYMENT
    dynEnt(5, 23, 0x4010E0);// DT_JMPREL
    dynEnt(6, 20, 17);      // DT_PLTREL: REL
    dynEnt(7, 4, 0x401120); // DT_HASH (SYSV)
    dynEnt(8, 0, 0);        // DT_NULL

    // dynsym at 0x2080: 3 x 16 bytes
    auto symEnt = [&](size_t i, uint32_t nameIdx, uint8_t info, uint16_t shndx) {
        size_t o = 0x2080 + i * 16;
        putU32(b, o, nameIdx);
        b[o + 12] = info;
        putU16(b, o + 14, shndx);
    };
    symEnt(0, 0, 0, 0);
    symEnt(1, 1, 0x12, 0);  // puts, GLOBAL FUNC UND
    symEnt(2, 16, 0x12, 1); // my32func, GLOBAL FUNC defined @ 0x400130
    putU32(b, 0x2080 + 2 * 16 + 4, 0x400130);

    // dynstr at 0x20C0: "\0puts\0libc.so.6\0my32func\0"
    putStr(b, 0x20C1, "puts");
    putStr(b, 0x20C6, "libc.so.6");
    putStr(b, 0x20D0, "my32func");

    // SYSV hash table at 0x2120 (vaddr 0x401120): nchain = 3 dynsyms
    putU32(b, 0x2120, 1);   // nbuckets
    putU32(b, 0x2124, 3);   // nchain
    putU32(b, 0x2128, 1);   // buckets[0] = symbol 1 (puts)
    putU32(b, 0x212C, 0);   // chains[0]
    putU32(b, 0x2130, 1);   // chains[1] = 1 (puts, end of chain)
    putU32(b, 0x2134, 0);   // chains[2]

    // .rel.plt at 0x20E0: puts -> 0x40110C
    putU32(b, 0x20E0, 0x40110C);            // r_offset
    putU32(b, 0x20E4, (1u << 8) | 7u);      // r_info: sym 1, JUMP_SLOT

    // GOT at 0x2100: [0],[1] reserved, [2] resolver, [3] puts slot
    putU32(b, 0x2100, 0);
    putU32(b, 0x2104, 0);
    putU32(b, 0x2108, 0x400106);
    putU32(b, 0x210C, 0);

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

// Imports with a real image address (GOT slots + PLT stubs), excluding the
// address-0 "(dynamic)" library records. The aarch64 corpus ELF's .dynstr
// section header is bogus, so the section path emits a garbage library name
// while the stripped path resolves the true DT_NEEDED names; the addresses
// are what GP-7056 must match.
static std::vector<std::pair<std::string, uint64_t>> importSetAddressed(BinaryLoader* l) {
    std::vector<std::pair<std::string, uint64_t>> v;
    for (const auto& imp : l->getImports()) {
        if (imp.address > 0) v.emplace_back(imp.functionName, imp.address);
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
          prog("elf_pltgot_test", nullptr, nullptr) {
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
    const char* src = ENIGMA_SOURCE_DIR;

    // ---------- Synthetic stripped ELF64 (RELA, x86-64) ----------
    const std::string p64 = "test_elf_pltgot64.bin";
    {
        std::ofstream out(p64, std::ios::binary);
        std::vector<uint8_t> bytes = buildStrippedELF64();
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    auto l64 = createLoader();
    TEST("ELF64 load stripped", l64->load(p64));
    TEST("ELF64 format", l64->getFormatName() == "ELF");
    TEST("ELF64 arch x86-64", l64->getArchitecture() == "x86" && l64->getBitness() == 64);
    {
        auto secs = l64->getSections();
        TEST("ELF64 segments synthesized", secs.size() == 2 &&
             secs[0].name == "seg_0" && secs[1].name == "seg_1");
    }
    {
        auto imp = l64->getImports();
        std::vector<std::pair<std::string, uint64_t>> expect = {
            {"(dynamic)", 0},      // libc.so.6 record
            {"puts", 0x401230},    // GOT slot
            {"puts", 0x400110},    // PLT stub
            {"printf", 0x401238},
            {"printf", 0x400120},
            {"_g_data", 0x401240}, // GLOB_DAT
        };
        std::sort(expect.begin(), expect.end());
        TEST("ELF64 imports match", importSet(l64.get()) == expect);
    }
    {
        bool found = false;
        for (const auto& s : l64->getSymbols())
            if (s.name == "my_func") found = s.address == 0x400180 && s.isFunction;
        TEST("ELF64 GNU hash sizes dynsym (my_func found)", found);
    }

    // ---------- Synthetic stripped ELF32 (REL, x86) ----------
    const std::string p32 = "test_elf_pltgot32.bin";
    {
        std::ofstream out(p32, std::ios::binary);
        std::vector<uint8_t> bytes = buildStrippedELF32();
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    auto l32 = createLoader();
    TEST("ELF32 load stripped", l32->load(p32));
    TEST("ELF32 format", l32->getFormatName() == "ELF");
    TEST("ELF32 arch x86-32", l32->getArchitecture() == "x86" && l32->getBitness() == 32);
    {
        auto imp = l32->getImports();
        std::vector<std::pair<std::string, uint64_t>> expect = {
            {"(dynamic)", 0},
            {"puts", 0x40110C},
            {"puts", 0x400110},
        };
        std::sort(expect.begin(), expect.end());
        TEST("ELF32 imports match", importSet(l32.get()) == expect);
    }
    {
        bool found = false;
        for (const auto& s : l32->getSymbols())
            if (s.name == "my32func") found = s.address == 0x400130 && s.isFunction;
        TEST("ELF32 SYSV hash sizes dynsym (my32func found)", found);
    }

    // ---------- populateProgram maps the synthesized segments ----------
    TestProgram tprog;
    TEST("ELF64 populateProgram", l64->populateProgram(&tprog.prog));
    {
        Memory* mem = tprog.prog.getMemory();
        TEST("ELF64 block at text", mem && mem->getBlock(tprog.ram(0x400000)) != nullptr);
        SymbolTable* st = tprog.prog.getSymbolTable();
        TEST("ELF64 label at GOT slot", st->hasSymbol(tprog.ram(0x401230)));
        TEST("ELF64 label at PLT stub", st->hasSymbol(tprog.ram(0x400110)));
        TEST("ELF64 label at GLOB_DAT slot", st->hasSymbol(tprog.ram(0x401240)));
    }

    // ---------- Real corpus ELFs: stripped == unstripped import sets ----------
    {
        std::string orig = std::string(src) + "/tests/corpus/x64_dyn.elf";
        std::string strip = std::string(src) + "/test_binaries/x64_dyn_stripped.elf";
        auto lo = createLoader(), ls = createLoader();
        TEST("x64 original loads", lo->load(orig));
        TEST("x64 stripped loads", ls->load(strip));
        auto oi = importSet(lo.get()), si = importSet(ls.get());
        TEST("x64 stripped imports non-empty", !si.empty());
        TEST("x64 stripped == original imports", oi == si);
    }
    {
        std::string orig = std::string(src) + "/tests/corpus/aarch64_pie_dyn.elf";
        std::string strip = std::string(src) + "/test_binaries/aarch64_dyn_stripped.elf";
        auto lo = createLoader(), ls = createLoader();
        TEST("aarch64 original loads", lo->load(orig));
        TEST("aarch64 stripped loads", ls->load(strip));
        auto oi = importSet(lo.get()), si = importSet(ls.get());
        TEST("aarch64 stripped imports non-empty", !si.empty());
        TEST("aarch64 stripped == original addressed imports",
             importSetAddressed(lo.get()) == importSetAddressed(ls.get()));
    }

    std::remove(p64.c_str());
    std::remove(p32.c_str());
    std::cout << "ELF PLTGOT Recovery Tests: " << passed << "/" << total << " passed.\n" << std::flush;
    return (passed == total) ? 0 : 1;
}