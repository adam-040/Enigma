/**
 * Enigma Engine - PE Loader Export-Forwarder Test (GP-5900 / Task 2.1)
 * A synthetic PE32+ with one normal export and one forwarded export
 * ("NTDLL.RtlAllocateHeap") verifies that:
 *   - parseExports detects the forwarder (RVA inside the export directory);
 *   - no bogus image-space function/label is created at the forwarder RVA;
 *   - the forwarder becomes a thunk function in EXTERNAL space whose
 *     thunked function is external and named after the forwarding string.
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <cstring>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/ExternalManager.h"
#include "ghidra/SymbolTable.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/Function.h"

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

// Section RVA 0x1000 <-> file offset 0x200.
static std::vector<uint8_t> buildForwarderPE() {
    std::vector<uint8_t> b(0x400, 0);

    // DOS header
    putU16(b, 0x00, 0x5A4D);             // "MZ"
    putU32(b, 0x3C, 0x40);               // e_lfanew

    // PE signature + COFF header
    putU32(b, 0x40, 0x00004550);         // "PE\0\0"
    putU16(b, 0x44, 0x8664);             // Machine: AMD64
    putU16(b, 0x46, 1);                  // NumberOfSections
    putU16(b, 0x54, 0xF0);               // SizeOfOptionalHeader
    putU16(b, 0x56, 0x2022);             // Characteristics

    // Optional header (PE32+)
    putU16(b, 0x58, 0x20B);              // Magic
    putU32(b, 0x5C, 0x200);              // SizeOfCode
    putU32(b, 0x60, 0);                  // SizeOfInitializedData
    putU32(b, 0x64, 0);                  // SizeOfUninitializedData
    putU32(b, 0x68, 0x1000);             // AddressOfEntryPoint
    putU32(b, 0x6C, 0x1000);             // BaseOfCode
    putU64(b, 0x70, 0x140000000ULL);     // ImageBase
    putU32(b, 0x78, 0x1000);             // SectionAlignment
    putU32(b, 0x7C, 0x200);              // FileAlignment
    putU16(b, 0x80, 6);                  // MajorOperatingSystemVersion
    putU16(b, 0x86, 6);                  // MajorSubsystemVersion
    putU32(b, 0x90, 0x2000);             // SizeOfImage
    putU32(b, 0x94, 0x200);              // SizeOfHeaders
    putU16(b, 0x9C, 3);                  // Subsystem: console
    putU64(b, 0xA0, 0x100000);           // SizeOfStackReserve
    putU64(b, 0xA8, 0x1000);             // SizeOfStackCommit
    putU64(b, 0xB0, 0x100000);           // SizeOfHeapReserve
    putU64(b, 0xB8, 0x1000);             // SizeOfHeapCommit
    putU32(b, 0xC4, 16);                 // NumberOfRvaAndSizes
    putU32(b, 0xC8, 0x1000);             // Export dir RVA (opt+112)
    putU32(b, 0xCC, 0x80);               // Export dir Size  (opt+116)

    // Section table: ".exp"
    std::memcpy(b.data() + 0x148, ".exp", 4);
    putU32(b, 0x150, 0x80);              // VirtualSize
    putU32(b, 0x154, 0x1000);            // VirtualAddress
    putU32(b, 0x158, 0x200);             // SizeOfRawData
    putU32(b, 0x15C, 0x200);             // PointerToRawData
    putU32(b, 0x16C, 0x40000040);        // INITIALIZED_DATA | READ

    // Export directory (RVA 0x1000 = file 0x200)
    putU32(b, 0x20C, 0x1050);            // Name RVA: "KERNEL32.dll"
    putU32(b, 0x210, 1);                 // Base ordinal
    putU32(b, 0x214, 2);                 // NumberOfFunctions
    putU32(b, 0x218, 2);                 // NumberOfNames
    putU32(b, 0x21C, 0x1028);            // AddressOfFunctions
    putU32(b, 0x220, 0x1030);            // AddressOfNames
    putU32(b, 0x224, 0x1038);            // AddressOfNameOrdinals

    // Functions: [0] normal in-image code RVA, [1] forwarder RVA
    putU32(b, 0x228, 0x1100);
    putU32(b, 0x22C, 0x1070);

    // Names: "NormalFunc", "ForwardedFunc"
    putU32(b, 0x230, 0x1040);
    putU32(b, 0x234, 0x1060);

    // Ordinals: 0, 1
    putU16(b, 0x238, 0);
    putU16(b, 0x23A, 1);

    // Strings
    putStr(b, 0x240, "NormalFunc");
    putStr(b, 0x250, "KERNEL32.dll");
    putStr(b, 0x260, "ForwardedFunc");
    putStr(b, 0x270, "NTDLL.RtlAllocateHeap");

    return b;
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
          prog("pe_forwarder_test", nullptr, nullptr) {
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
    const std::string path = "test_pe_forwarder.bin";
    {
        std::ofstream out(path, std::ios::binary);
        std::vector<uint8_t> bytes = buildForwarderPE();
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }

    auto loader = createLoader();
    TEST("load synthetic PE", loader->load(path));
    TEST("format PE", loader->getFormatName() == "PE");
    TEST("arch x86-64", loader->getArchitecture() == "x86" && loader->getBitness() == 64);

    auto exports = loader->getExports();
    TEST("two exports parsed", exports.size() == 2);
    if (exports.size() == 2) {
        const ExportInfo& normal = exports[0];
        TEST("normal export name", normal.name == "NormalFunc");
        TEST("normal export address", normal.address == 0x140001100ULL);
        TEST("normal export not forwarder", !normal.isForwarder);
        const ExportInfo& fwd = exports[1];
        TEST("forwarder export name", fwd.name == "ForwardedFunc");
        TEST("forwarder flag set", fwd.isForwarder);
        TEST("forwarder string", fwd.forwarderString == "NTDLL.RtlAllocateHeap");
        TEST("forwarder dll name", fwd.dllName == "KERNEL32.dll");
        TEST("forwarder has no image address", fwd.address == 0);
    }

    TestProgram tprog;
    TEST("populateProgram", loader->populateProgram(&tprog.prog));

    FunctionManager* fm = tprog.prog.getFunctionManager();
    ExternalManager* externals = tprog.prog.getExternalManager();
    SymbolTable* symTable = tprog.prog.getSymbolTable();

    // No bogus image-space artifacts at the forwarder RVA.
    Address bogusImage = tprog.ram(0x140001070ULL);
    TEST("no image function at forwarder RVA", fm->getFunctionAt(bogusImage) == nullptr);
    TEST("no image label at forwarder RVA", !symTable->hasSymbol(bogusImage));

    // Normal export keeps its image-space label.
    Address normalAddr = tprog.ram(0x140001100ULL);
    TEST("normal export label", symTable->hasSymbol(normalAddr));
    TEST("normal export function", fm->getFunctionAt(normalAddr) != nullptr);

    // EXTERNAL space + external locations.
    AddressSpace* extSpace = const_cast<AddressSpace*>(
        tprog.prog.getAddressFactory()->getAddressSpace("EXTERNAL"));
    TEST("EXTERNAL space exists", extSpace != nullptr);
    TEST("EXTERNAL space typed external",
         extSpace && extSpace->isExternalSpace());

    ExternalLocation* targetLoc = externals ? externals->getExternalLocation("NTDLL", "RtlAllocateHeap") : nullptr;
    TEST("target external location", targetLoc != nullptr);
    if (targetLoc) {
        TEST("target location label", targetLoc->getLabel() == "RtlAllocateHeap");
        TEST("target location library", targetLoc->getLibraryName() == "NTDLL");
        TEST("target location is function", targetLoc->isExternalFunction());
    }

    ExternalLocation* thunkLoc = externals ? externals->getExternalLocation("KERNEL32.dll", "ForwardedFunc") : nullptr;
    TEST("thunk external location", thunkLoc != nullptr);
    if (thunkLoc) {
        TEST("thunk location original import name", thunkLoc->getOriginalImportedName() == "NTDLL.RtlAllocateHeap");
    }

    // The forwarder thunk function -> external target function.
    Function* thunk = nullptr;
    FunctionIterator it = fm->getFunctions(true);
    while (it.hasNext()) {
        Function* f = it.next();
        if (f && f->isThunk()) thunk = f;
    }
    TEST("thunk function exists", thunk != nullptr);
    if (thunk) {
        TEST("thunk name", thunk->getName() == "ForwardedFunc");
        TEST("thunk is external", thunk->isExternal());
        TEST("thunk in EXTERNAL space",
             thunk->getEntryPoint().isExternalAddress());
        Function* target = thunk->getThunkedFunction();
        TEST("thunked function exists", target != nullptr);
        if (target) {
            TEST("thunked function external", target->isExternal());
            TEST("thunked function name", target->getName() == "RtlAllocateHeap");
            TEST("thunked function not a thunk", !target->isThunk());
        }
    }

    std::remove(path.c_str());
    std::cout << "PE Loader Forwarder Tests: " << passed << "/" << total << " passed.\n" << std::flush;
    return (passed == total) ? 0 : 1;
}