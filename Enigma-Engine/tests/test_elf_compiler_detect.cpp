/**
 * Enigma Engine - ELF compiler recognition and symbol external-ness test
 * Covers GP-3960 (ELF Swift/golang recognition) and GP-7057 (ElfSymbol.isExternal).
 */
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cstdlib>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

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

static void putBytes(std::vector<uint8_t>& b, size_t off, const uint8_t* src, size_t n) {
    for (size_t i = 0; i < n; ++i) b[off + i] = src[i];
}

struct Elf64Fixture {
    std::vector<uint8_t> data;
    std::vector<size_t> shNameOffsets;
    std::string shstr;
};

// Builds an ELF64 with the given extra section names (plus mandatory .text/.shstrtab).
// When withSymtab is set, a .symtab/.strtab pair is added with two defined symbols.
static Elf64Fixture buildSyntheticELF64(const std::vector<std::string>& extraNames,
                                        bool withSymtab) {
    Elf64Fixture fx;
    fx.shstr.assign(1, '\0');
    std::vector<std::string> names;
    names.push_back(".text");
    for (const auto& n : extraNames) {
        names.push_back(n);
    }
    if (withSymtab) {
        names.push_back(".symtab");
        names.push_back(".strtab");
    }
    names.push_back(".shstrtab");

    fx.shNameOffsets.assign(names.size(), 0);
    size_t strPos = 1;
    for (size_t i = 0; i < names.size(); ++i) {
        fx.shNameOffsets[i] = strPos;
        fx.shstr += names[i];
        fx.shstr += '\0';
        strPos += names[i].size() + 1;
    }

    const size_t shstrIndex = names.size() - 1;
    size_t fileSize = 0x100 + names.size() * 64;
    std::vector<uint8_t> b(fileSize, 0);

    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2;                       // ELF64
    b[5] = 1;                       // little endian
    b[6] = 1;                       // EV_CURRENT
    b[7] = 0;                       // System V ABI
    putU16(b, 16, 3);               // e_type = ET_DYN
    putU16(b, 18, 62);              // e_machine = EM_X86_64
    putU32(b, 20, 1);               // e_version
    putU64(b, 24, 0x401000);        // e_entry
    putU64(b, 32, 0);               // e_phoff
    putU64(b, 40, 0x100);           // e_shoff
    putU32(b, 48, 0);               // e_flags
    putU16(b, 52, 64);              // e_ehsize
    putU16(b, 54, 0);               // e_phentsize
    putU16(b, 56, 0);               // e_phnum
    putU16(b, 58, 64);              // e_shentsize
    putU16(b, 60, static_cast<uint16_t>(names.size()));  // e_shnum
    putU16(b, 62, static_cast<uint16_t>(shstrIndex));    // e_shstrndx

    size_t fileOff = 0x40;
    auto addSection = [&](size_t idx, uint32_t type, uint64_t addr, uint64_t size,
                          uint64_t flags) {
        size_t so = 0x100 + idx * 64;
        putU32(b, so, static_cast<uint32_t>(fx.shNameOffsets[idx]));
        putU32(b, so + 4, type);
        putU64(b, so + 8, flags);
        putU64(b, so + 16, addr);
        putU64(b, so + 24, fileOff);
        putU64(b, so + 32, size);
        putU64(b, so + 48, type == 3 ? 1 : 1);
        size_t start = fileOff;
        fileOff += size;
        return start;
    };

    size_t textIdx = 0;
    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i] == ".text") { textIdx = i; break; }
    }
    addSection(textIdx, 1, 0x401000, 0x10, 0x6);  // .text SHF_ALLOC|SHF_EXECINSTR

    // Give every remaining named section a resolvable name so compiler detection
    // sees them (size 0 -> no memory block created).
    for (size_t i = 0; i < names.size(); ++i) {
        if (i == textIdx || names[i] == ".symtab" || names[i] == ".strtab" ||
            names[i] == ".shstrtab") {
            continue;
        }
        putU32(b, 0x100 + i * 64, static_cast<uint32_t>(fx.shNameOffsets[i]));
    }

    size_t symtabIdx = 0, strtabIdx = 0;
    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i] == ".symtab") symtabIdx = i;
        if (names[i] == ".strtab") strtabIdx = i;
    }
    if (withSymtab) {
        size_t symOff = addSection(symtabIdx, 2, 0x501000, 3 * 24, 0);
        size_t strOff = addSection(strtabIdx, 3, 0x502000, 24, 0);
        putU32(b, 0x100 + symtabIdx * 64 + 40, static_cast<uint32_t>(strtabIdx));
        putU32(b, 0x100 + symtabIdx * 64 + 56, 24);
        // .strtab: "main\0weak_fn\0undefined\0"
        b[strOff + 0] = 0;
        putBytes(b, strOff + 1, reinterpret_cast<const uint8_t*>("main"), 4);
        b[strOff + 5] = 0;
        putBytes(b, strOff + 6, reinterpret_cast<const uint8_t*>("weak_fn"), 7);
        b[strOff + 13] = 0;
        putBytes(b, strOff + 14, reinterpret_cast<const uint8_t*>("undefined"), 9);
        b[strOff + 23] = 0;
        // sym 0: null entry
        // sym 1: main, GLOBAL FUNC, defined in .text (shndx 1)
        putU32(b, symOff + 24, 1);
        b[symOff + 24 + 4] = 0x12;
        putU16(b, symOff + 24 + 6, 1);
        putU64(b, symOff + 24 + 8, 0x401000);
        putU64(b, symOff + 24 + 16, 8);
        // sym 2: weak_fn, WEAK FUNC, defined in .text (shndx 1)
        putU32(b, symOff + 48, 6);
        b[symOff + 48 + 4] = 0x22;
        putU16(b, symOff + 48 + 6, 1);
        putU64(b, symOff + 48 + 8, 0x401008);
        putU64(b, symOff + 48 + 16, 8);
        // sym 3 (unused in this layout): undefined GLOBAL FUNC, shndx 0, value 0
    }

    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i] == ".shstrtab") {
            size_t shstrFileOff = addSection(i, 3, 0x503000, fx.shstr.size(), 0);
            size_t off = 0x100 + i * 64;
            putU32(b, off + 40, 1);
            putU32(b, off + 56, 1);
            putBytes(b, shstrFileOff, reinterpret_cast<const uint8_t*>(fx.shstr.data()),
                     fx.shstr.size());
        }
    }

    fx.data = b;
    return fx;
}

static std::string writeTempFile(const std::vector<uint8_t>& data, const char* tag) {
    std::string path = std::string(std::getenv("TEMP") ? std::getenv("TEMP") : ".")
        + "\\enigma_compiler_detect_" + tag + ".elf";
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.close();
    return path;
}

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
          prog("compiler_detect_test", nullptr, nullptr) {
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

static bool loadAndPopulate(const std::string& path, ghidra::BinaryLoader* loader,
                            TestProgram& prog) {
    if (!loader->load(path)) return false;
    return loader->populateProgram(&prog.prog);
}

int main() {
    std::cout << "=== Enigma Engine - ELF Compiler Detection Test ===" << std::endl;

    {
        std::cout << "\n--- Test 1: Go ELF detection (GP-3960) ---" << std::endl;
        Elf64Fixture fx = buildSyntheticELF64({ ".gopclntab" }, false);
        std::string path = writeTempFile(fx.data, "go");
        auto loader = ghidra::createLoader();
        TestProgram prog;
        bool ok = loadAndPopulate(path, loader.get(), prog);
        TEST("Go ELF loaded", ok);
        TEST("Format is ELF", ok && loader->getFormatName() == "ELF");
        TEST("Compiler is golang", ok && prog.prog.getCompiler() == "golang");
        TEST("Compiler spec is golang", ok &&
             prog.prog.getCompilerSpecID().toString() == "golang");
    }

    {
        std::cout << "\n--- Test 2: Swift ELF detection (GP-3960) ---" << std::endl;
        Elf64Fixture fx = buildSyntheticELF64({ "__swift5_types" }, false);
        std::string path = writeTempFile(fx.data, "swift");
        auto loader = ghidra::createLoader();
        TestProgram prog;
        bool ok = loadAndPopulate(path, loader.get(), prog);
        TEST("Swift ELF loaded", ok);
        TEST("Compiler is swift", ok && prog.prog.getCompiler() == "swift");
        TEST("Compiler spec is swift", ok &&
             prog.prog.getCompilerSpecID().toString() == "swift");
    }

    {
        std::cout << "\n--- Test 3: Plain ELF stays default (GP-3960) ---" << std::endl;
        Elf64Fixture fx = buildSyntheticELF64({}, false);
        std::string path = writeTempFile(fx.data, "plain");
        auto loader = ghidra::createLoader();
        TestProgram prog;
        bool ok = loadAndPopulate(path, loader.get(), prog);
        TEST("Plain ELF loaded", ok);
        TEST("Compiler not set", ok && prog.prog.getCompiler().empty());
        TEST("Compiler spec stays arch-guessed", ok &&
             prog.prog.getCompilerSpecID().toString() == "windows");
    }

    {
        std::cout << "\n--- Test 4: isExternal semantics (GP-7057) ---" << std::endl;
        Elf64Fixture fx = buildSyntheticELF64({}, true);
        std::string path = writeTempFile(fx.data, "sym");
        auto loader = ghidra::createLoader();
        TestProgram prog;
        bool ok = loadAndPopulate(path, loader.get(), prog);
        TEST("ELF with symtab loaded", ok);
        auto symbols = loader->getSymbols();
        TEST("Two defined symbols parsed", ok && symbols.size() == 2);
        TEST("Global FUNC symbol present", ok && symbols.size() == 2 &&
             symbols[0].name == "main" && symbols[0].isFunction);
        TEST("Weak FUNC symbol present", ok && symbols.size() == 2 &&
             symbols[1].name == "weak_fn" && symbols[1].isFunction);
        TEST("Defined global not external (GP-7057)", ok && symbols.size() == 2 &&
             !symbols[0].isExternal);
        TEST("Defined weak not external (GP-7057)", ok && symbols.size() == 2 &&
             !symbols[1].isExternal);
    }

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << passed << "/" << total << " tests passed" << std::endl;
    return (passed == total) ? 0 : 1;
}