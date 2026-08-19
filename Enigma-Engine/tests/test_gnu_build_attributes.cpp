/**
 * Enigma Engine - ELF .gnu.build.attributes markup test (GP-5929)
 * Builds a synthetic ELF64 with a .gnu.build.attributes section containing
 * three GNU build attribute notes, runs ElfAnalyzer, and verifies the
 * markup: labels, comments, data structures and range references.
 */
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/AddressSet.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/ElfAnalyzer.h"
#include "ghidra/TaskMonitor.h"
#include "ghidra/MessageLog.h"
#include "ghidra/Listing.h"
#include "ghidra/Data.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/ReferenceManager.h"
#include "ghidra/Reference.h"
#include "ghidra/Msg.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

struct TestProgram {
    ghidra::GenericAddressSpace ramSpace;
    ghidra::GenericAddressSpace constSpace;
    ghidra::GenericAddressSpace uniqueSpace;
    ghidra::GenericAddressSpace registerSpace;
    ghidra::GenericAddressSpace stackSpace;
    ghidra::ProgramDB prog;

    TestProgram()
        : ramSpace("ram", 64, ghidra::AddressSpace::TYPE_RAM, 1),
          constSpace("const", 64, ghidra::AddressSpace::TYPE_CONSTANT, 2),
          uniqueSpace("unique", 64, ghidra::AddressSpace::TYPE_UNIQUE, 3),
          registerSpace("register", 64, ghidra::AddressSpace::TYPE_REGISTER, 4),
          stackSpace("stack", 64, ghidra::AddressSpace::TYPE_STACK, 5),
          prog("gnu_attr_test", nullptr, nullptr) {
        auto* addrFactory = dynamic_cast<ghidra::ProgramAddressFactory*>(prog.getAddressFactory());
        if (addrFactory) {
            addrFactory->addAddressSpace(&ramSpace);
            addrFactory->setDefaultSpace(&ramSpace);
            addrFactory->setConstantSpace(&constSpace);
            addrFactory->setUniqueSpace(&uniqueSpace);
            addrFactory->setRegisterSpace(&registerSpace);
            addrFactory->setStackSpace(&stackSpace);
        }
    }
};

static void putU16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

static void putU32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    b[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    b[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static void putU64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[off + static_cast<size_t>(i)] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    }
}

static void putBytes(std::vector<uint8_t>& b, size_t off, const uint8_t* src, size_t n) {
    std::memcpy(b.data() + off, src, n);
}

static std::vector<uint8_t> buildSyntheticELF() {
    // Layout:
    // 0x000: ELF64 header
    // 0x040: .text (0x80 NOP bytes), vaddr 0x400000
    // 0x0C0: .gnu.build.attributes content (88 bytes: 36 + 20 + 32)
    // 0x120: .shstrtab
    // 0x150: 4 section headers (64 bytes each)
    std::vector<uint8_t> b(0x150 + 4 * 64, 0);

    const uint8_t ident[16] = {0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    putBytes(b, 0, ident, 16);
    putU16(b, 16, 2);            // e_type = EXEC
    putU16(b, 18, 0x3E);         // e_machine = x86-64
    putU32(b, 20, 1);            // e_version
    putU64(b, 24, 0x400000);     // e_entry
    putU64(b, 32, 0);            // e_phoff (no program headers)
    putU64(b, 40, 0x150);        // e_shoff
    putU32(b, 48, 0);            // e_flags
    putU16(b, 52, 64);           // e_ehsize
    putU16(b, 54, 56);           // e_phentsize
    putU16(b, 56, 0);            // e_phnum
    putU16(b, 58, 64);           // e_shentsize
    putU16(b, 60, 4);            // e_shnum
    putU16(b, 62, 3);            // e_shstrndx

    // .text: NOPs
    for (size_t i = 0; i < 0x80; ++i) b[0x40 + i] = 0x90;

    // .gnu.build.attributes content at 0xC0
    size_t c = 0xC0;
    // Note 1: OPEN range attribute, id=VERSION, value "3a1"
    // name = "GA$" + 0x01 + "3a1\0"
    const uint8_t note1Name[8] = {'G', 'A', '$', 0x01, '3', 'a', '1', 0};
    putU32(b, c, 8);             // namesz
    putU32(b, c + 4, 16);        // descsz
    putU32(b, c + 8, 0x100);     // type = OPEN
    putBytes(b, c + 12, note1Name, 8);
    putU64(b, c + 20, 0x400000);   // range start
    putU64(b, c + 28, 0x400101);   // range end (exclusive)
    c += 36;
    // Note 2: FUNC attribute, id=STACK_PROT(2), numeric value 3
    const uint8_t note2Name[5] = {'G', 'A', '*', 0x02, 0x03};
    putU32(b, c, 5);             // namesz
    putU32(b, c + 4, 0);         // descsz
    putU32(b, c + 8, 0x101);     // type = FUNC
    putBytes(b, c + 12, note2Name, 5);
    c += 20;
    // Note 3: OPEN attribute with string-valued id "myattr", value "myvalue"
    // name = "GA$\"" + "myattr\0" + "myvalue\0"
    const uint8_t note3Name[19] = {'G', 'A', '$', '"',
                                   'm', 'y', 'a', 't', 't', 'r', 0,
                                   'm', 'y', 'v', 'a', 'l', 'u', 'e', 0};
    putU32(b, c, 19);            // namesz
    putU32(b, c + 4, 0);         // descsz
    putU32(b, c + 8, 0x100);     // type = OPEN
    putBytes(b, c + 12, note3Name, 19);
    c += 32;

    // .shstrtab at 0x120
    const char shstr[] = "\0.text\0.gnu.build.attributes\0.shstrtab\0";
    const size_t shstrLen = sizeof(shstr) - 1;
    for (size_t i = 0; i < shstrLen; ++i) b[0x120 + i] = static_cast<uint8_t>(shstr[i]);

    // Section headers at 0x150
    auto shdr = [&](size_t idx) -> size_t { return 0x150 + idx * 64; };
    // [0] null
    // [1] .text
    putU32(b, shdr(1) + 0, 1);           // sh_name
    putU32(b, shdr(1) + 4, 1);           // sh_type = PROGBITS
    putU64(b, shdr(1) + 8, 0x6);         // sh_flags = AX
    putU64(b, shdr(1) + 16, 0x400000);   // sh_addr
    putU64(b, shdr(1) + 24, 0x40);       // sh_offset
    putU64(b, shdr(1) + 32, 0x80);       // sh_size
    putU64(b, shdr(1) + 48, 16);         // sh_addralign
    // [2] .gnu.build.attributes
    putU32(b, shdr(2) + 0, 7);           // sh_name
    putU32(b, shdr(2) + 4, 0x6FFFFFF5);  // sh_type = SHT_GNU_ATTRIBUTES
    putU64(b, shdr(2) + 8, 0);           // sh_flags
    putU64(b, shdr(2) + 16, 0x400200);   // sh_addr
    putU64(b, shdr(2) + 24, 0xC0);       // sh_offset
    putU64(b, shdr(2) + 32, 88);         // sh_size
    putU64(b, shdr(2) + 48, 4);          // sh_addralign
    // [3] .shstrtab
    putU32(b, shdr(3) + 0, 29);          // sh_name
    putU32(b, shdr(3) + 4, 3);           // sh_type = STRTAB
    putU64(b, shdr(3) + 8, 0);           // sh_flags
    putU64(b, shdr(3) + 16, 0x1000);     // sh_addr (avoid the ELF_HEADER block at 0)
    putU64(b, shdr(3) + 24, 0x120);      // sh_offset
    putU64(b, shdr(3) + 32, shstrLen);   // sh_size
    putU64(b, shdr(3) + 48, 1);          // sh_addralign

    return b;
}

int main(int argc, char** argv) {
    std::cout << "=== Enigma Engine - ELF .gnu.build.attributes Markup Test ===" << std::endl;

    std::string elfPath = "C:\\Users\\pc\\AppData\\Local\\Temp\\opencode\\gnu_attr_test.elf";
    const char* envPath = std::getenv("ENIGMA_TEST_ELF_PATH");
    if (envPath && *envPath) elfPath = envPath;

    {
        std::vector<uint8_t> elf = buildSyntheticELF();
        std::ofstream out(elfPath, std::ios::binary);
        if (!out) {
            std::cerr << "Failed to write synthetic ELF to " << elfPath << std::endl;
            return 1;
        }
        out.write(reinterpret_cast<const char*>(elf.data()), static_cast<std::streamsize>(elf.size()));
    }

    auto loader = ghidra::createLoader();
    TEST("Loader created", loader != nullptr);
    if (!loader) return 1;

    bool parsed = loader->load(elfPath);
    TEST("Synthetic ELF parsed", parsed);
    TEST("Format is ELF", parsed && loader->getFormatName() == "ELF");

    TestProgram tprog;
    bool loaded = loader->populateProgram(&tprog.prog);
    TEST("ProgramDB populated", loaded);
    if (!loaded) {
        std::cout << "GNU build attributes tests: " << passed << "/" << total << " passed.\n";
        return (passed == total) ? 0 : 1;
    }

    ghidra::ElfAnalyzer analyzer;
    ghidra::StubTaskMonitor monitor;
    ghidra::MessageLog log;
    ghidra::AddressSet emptySet;
    bool ok = analyzer.added(&tprog.prog, emptySet, &monitor, log);
    TEST("ElfAnalyzer.added completes", ok);

    auto* symTable = tprog.prog.getSymbolTable();
    auto* listing = tprog.prog.getListing();
    auto* refMgr = tprog.prog.getReferenceManager();

    ghidra::AddressSpace* ram = const_cast<ghidra::AddressSpace*>(
        tprog.prog.getAddressFactory()->getDefaultAddressSpace());

    // Note 1: gnu.build.attribute_OPEN_VERSION=3a1 at 0x400200
    {
        auto it = symTable->getSymbols("gnu.build.attribute_OPEN_VERSION=3a1");
        TEST("Note1 label created", it.hasNext());

        ghidra::Address note1Addr(ram, 0x400200);
        ghidra::Data* d = listing->getDefinedDataContaining(note1Addr);
        TEST("Note1 data defined", d != nullptr);
        if (d) {
            const std::string& cm = d->getComment();
            TEST("Note1 comment has VERSION=3a1", cm.find("VERSION=3a1") != std::string::npos);
            TEST("Note1 comment has range", cm.find("range=") != std::string::npos);
        }

        auto refs = refMgr->getReferencesFrom(ghidra::Address(ram, 0x400214));
        bool foundStart = false;
        for (auto* ref : refs) {
            if (ref && ref->getToAddress() == ghidra::Address(ram, 0x400000)) foundStart = true;
        }
        auto endRefs = refMgr->getReferencesFrom(ghidra::Address(ram, 0x40021C));
        bool foundEnd = false;
        for (auto* ref : endRefs) {
            if (ref && ref->getToAddress() == ghidra::Address(ram, 0x400100)) foundEnd = true;
        }
        TEST("Note1 range start reference", foundStart);
        TEST("Note1 range end reference", foundEnd);
    }

    // Note 2: gnu.build.attribute_FUNC_STACK_PROT=3 at 0x400224
    {
        auto it = symTable->getSymbols("gnu.build.attribute_FUNC_STACK_PROT=3");
        TEST("Note2 label created", it.hasNext());

        ghidra::Address note2Addr(ram, 0x400224);
        ghidra::Data* d = listing->getDefinedDataContaining(note2Addr);
        TEST("Note2 data defined", d != nullptr);
        if (d) {
            const std::string& cm = d->getComment();
            TEST("Note2 comment has STACK_PROT=3", cm.find("STACK_PROT=3") != std::string::npos);
        }
    }

    // Note 3: string-valued id "myattr" at 0x400238
    {
        ghidra::Address note3Addr(ram, 0x400238);
        ghidra::Data* d = listing->getDefinedDataContaining(note3Addr);
        TEST("Note3 data defined", d != nullptr);
        if (d) {
            const std::string& cm = d->getComment();
            TEST("Note3 comment has myattr", cm.find("myattr") != std::string::npos);
            TEST("Note3 comment has myvalue", cm.find("myvalue") != std::string::npos);
        }
    }

    std::cout << "GNU build attributes tests: " << passed << "/" << total << " passed.\n"
              << std::flush;
    return (passed == total) ? 0 : 1;
}