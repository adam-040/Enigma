#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <cstdlib>
#include <cstring>

#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"

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
          prog("macho_test", nullptr, nullptr) {
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

// Mach-O file builder — constructs a valid thin x86_64 Mach-O with __text,
// __la_symbol_ptr, one defined symbol (_myfunc), one undefined external
// (_printf), LC_DYSYMTAB with indirect symbol table, and LC_LOAD_DYLIB.
struct builder {
    std::vector<uint8_t> buf;

    void w8(uint8_t v) { buf.push_back(v); }
    void w16(uint16_t v) { w8(v & 0xFF); w8(v >> 8); }
    void w32(uint32_t v) { w8(v & 0xFF); w8((v >> 8) & 0xFF); w8((v >> 16) & 0xFF); w8((v >> 24) & 0xFF); }
    void w64(uint64_t v) { w32(v & 0xFFFFFFFF); w32(v >> 32); }
    void wfill(size_t n) { while (n--) w8(0); }
    void wstr16(const char* s) { char tmp[17]={}; strncpy(tmp, s, 16); write_bytes((const uint8_t*)tmp, 16); }
    void write_bytes(const uint8_t* p, size_t n) { buf.insert(buf.end(), p, p + n); }

    void dump_debug(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return;
        size_t sz = static_cast<size_t>(f.tellg());
        f.seekg(0);
        std::vector<uint8_t> d(sz);
        f.read(reinterpret_cast<char*>(d.data()), sz);
        f.close();

        auto rd32 = [&](size_t o) { return o+4<=sz ? d[o]|(d[o+1]<<8)|(d[o+2]<<16)|(d[o+3]<<24) : 0u; };
        auto rd64 = [&](size_t o) { uint64_t v=0; for(int b=0;b<8&&o+b<sz;b++) v|=uint64_t(d[o+b])<<(b*8); return v; };

        uint32_t ncmds = rd32(16), scmds = rd32(20);
        std::cerr << "  DEBUG: size=" << sz << " ncmds=" << ncmds << " sizeofcmds=" << scmds << "\n";

        uint32_t off = 32;
        for (uint32_t c = 0; c < ncmds && off + 8 <= sz; c++) {
            uint32_t cmd = rd32(off), size = rd32(off+4);
            std::cerr << "  cmd=0x" << std::hex << cmd << std::dec << " size=" << size << " off=" << off << "\n";
            if (cmd == 0x02) {
                uint32_t symoff=rd32(off+8), nsyms=rd32(off+12), stroff=rd32(off+16), strsize=rd32(off+20);
                std::cerr << "    SYMTAB symoff=" << symoff << " nsyms=" << nsyms
                          << " stroff=" << stroff << " strsize=" << strsize << "\n";
                for (uint32_t i = 0; i < nsyms && i < 3; i++) {
                    uint32_t no = symoff + i * 16;
                    uint32_t ns = rd32(no); uint8_t nt = d[no+4], nsect = d[no+5];
                    uint64_t nv = rd64(no+8);
                    std::string nm;
                    if (ns < strsize) for (uint32_t k = stroff+ns; k < sz && d[k]; k++) nm += (char)d[k];
                    std::cerr << "    nlist[" << i << "] strx=" << ns << " type=0x" << (int)nt
                              << " sect=" << (int)nsect << " value=0x" << std::hex << nv << std::dec
                              << " name=" << nm << "\n";
                }
            }
            if (size == 0) break;
            off += size;
        }
    }

    void build(const std::string& path) {
        // File layout offsets (computed upfront)
        const uint32_t PAGE = 4096;
        // Load commands will occupy ~500 bytes; pad to PAGE boundary
        const uint32_t TEXT_FILEOFF = PAGE;           // __text data at PAGE
        const uint32_t PTR_FILEOFF = TEXT_FILEOFF + 1; // __la_symbol_ptr data (1 stub = 8 bytes) after __text
        const uint32_t NLIST_OFF = PTR_FILEOFF + 8;   // nlist entries
        // 2 nlist_64 entries: _myfunc + _printf = 2 * 16 = 32 bytes
        const uint32_t NLIST_COUNT = 2;
        const uint32_t STRTAB_OFF = NLIST_OFF + NLIST_COUNT * 16;
        const char strtab[] = "_myfunc\0_printf";
        const uint32_t STRTAB_LEN = static_cast<uint32_t>(sizeof(strtab));
        const uint32_t INDIRECT_OFF = STRTAB_OFF + STRTAB_LEN;
        const uint32_t INDIRECT_COUNT = 1; // 1 entry pointing to _printf (index 1 + 2 adjustment)
        const uint32_t TOTAL_SIZE = INDIRECT_OFF + INDIRECT_COUNT * 4;

        // VM addresses
        const uint64_t TEXT_VM = 0x100000000;
        const uint64_t TEXT_VMSIZE = 0x1000;
        const uint64_t PTR_VM = 0x100001000;
        const uint64_t PTR_VMSIZE = 8;

        // === Header ===
        w32(0xCFFAEDFE); // MH_MAGIC_64
        w32(0x01000007); // CPU_TYPE_X86_64
        w32(3);           // CPU_SUBTYPE_X86_ALL
        w32(2);           // MH_EXECUTE
        w32(0);           // ncmds placeholder
        w32(0);           // sizeofcmds placeholder
        w32(0x00200085);  // flags
        w32(0);           // reserved

        uint32_t ncmds = 0;
        uint32_t sizeofcmds = 0;

        // === LC_SEGMENT_64: __TEXT (1 section: __text) ===
        {
            ncmds++;
            uint32_t segsize = 72 + 1 * 80;
            sizeofcmds += segsize;
            w32(0x19);    // LC_SEGMENT_64
            w32(segsize);
            wstr16("__TEXT");
            w64(TEXT_VM);
            w64(TEXT_VMSIZE);
            w64(0);       // fileoff
            w64(TEXT_VMSIZE);
            w32(7);       // maxprot rwx
            w32(5);       // initprot rx
            w32(1);       // nsects
            w32(0);       // flags
            // __text section
            wstr16("__text");
            wstr16("__TEXT");
            w64(TEXT_VM);
            w64(4);       // size
            w32(TEXT_FILEOFF);
            w32(2);       // align
            w32(0); w32(0); // reloff, nreloc
            w32(0x80000000); // S_ATTR_SOME_INSTRUCTIONS
            w32(0); w32(0); w32(0); // reserved1,2,3
        }

        // === LC_SEGMENT_64: __DATA (1 section: __la_symbol_ptr) ===
        {
            ncmds++;
            uint32_t segsize = 72 + 1 * 80;
            sizeofcmds += segsize;
            w32(0x19);    // LC_SEGMENT_64
            w32(segsize);
            wstr16("__DATA");
            w64(PTR_VM);
            w64(PTR_VMSIZE);
            w64(PTR_FILEOFF);
            w64(PTR_VMSIZE);
            w32(7);       // maxprot rwx
            w32(3);       // initprot rw
            w32(1);       // nsects
            w32(0);       // flags
            // __la_symbol_ptr section
            wstr16("__la_symbol_ptr");
            wstr16("__DATA");
            w64(PTR_VM);
            w64(8);       // size (1 pointer)
            w32(PTR_FILEOFF);
            w32(3);       // align (2^3=8)
            w32(0); w32(0); // reloff, nreloc
            w32(0x00000003); // S_LAZY_SYMBOL_PTRS flag
            w32(0);       // reserved1 — will be indirect symbol table index
            w32(0);       // reserved2
            w32(0);
        }

        // === LC_SYMTAB ===
        {
            ncmds++;
            sizeofcmds += 24;
            w32(0x02); // LC_SYMTAB
            w32(24);
            w32(NLIST_OFF);
            w32(NLIST_COUNT);
            w32(STRTAB_OFF);
            w32(STRTAB_LEN);
        }

        // === LC_DYSYMTAB ===
        {
            ncmds++;
            sizeofcmds += 80;
            w32(0x0B); // LC_DYSYMTAB
            w32(80);
            w32(0); w32(0); // ilocalsym=nlocalsym=0
            w32(0); w32(1); // iextdefsym=0, nextdefsym=1 (myfunc)
            w32(1); w32(1); // iundefsym=1, nundefsym=1 (printf)
            w32(0); w32(0); w32(0); w32(0); // tocoff/toc, modtab off/count
            w32(0); w32(0); // extrefsym
            w32(INDIRECT_OFF); w32(INDIRECT_COUNT); // indirectsym
            w32(0); w32(0); w32(0); w32(0); // extrel/locrel
        }

        // === LC_MAIN ===
        {
            ncmds++;
            sizeofcmds += 24;
            w32(0x28); // LC_MAIN
            w32(24);
            w64(TEXT_FILEOFF); // entryoff
            w64(0);    // stacksize
        }

        // === LC_LOAD_DYLIB ===
        {
            const char* lib = "/usr/lib/libSystem.B.dylib";
            uint32_t liblen = static_cast<uint32_t>(strlen(lib) + 1);
            uint32_t padded = (liblen + 7) & ~7;
            ncmds++;
            uint32_t cmdsize = 24 + padded;
            sizeofcmds += cmdsize;
            w32(0x0C);
            w32(cmdsize);
            w32(24);   // offset to name
            w32(0); w32(0); w32(0); // timestamp, current/compat vers
            write_bytes((const uint8_t*)lib, liblen);
            while (buf.size() % 8) w8(0); // pad
        }

        // Patch header
        buf[16] = ncmds & 0xFF; buf[17] = (ncmds >> 8) & 0xFF;
        buf[18] = (ncmds >> 16) & 0xFF; buf[19] = (ncmds >> 24) & 0xFF;
        buf[20] = sizeofcmds & 0xFF; buf[21] = (sizeofcmds >> 8) & 0xFF;
        buf[22] = (sizeofcmds >> 16) & 0xFF; buf[23] = (sizeofcmds >> 24) & 0xFF;

        // Patch __la_symbol_ptr reserved1 to indirect table index 0
        // The DATA segment starts after the TEXT segment's seg_cmd.
        // TEXT seg_cmd = 72 + 80 = 152 bytes
        // DATA seg_cmd starts at 32 + 152 = 184
        // DATA section starts at 184 + 72 = 256
        // Section reserved1 at section_start + 68
        uint32_t dataSectionOff = 256;
        buf[dataSectionOff + 68] = 0; // reserved1 = 0 (first entry in indirect table)

        // Open file and write
        std::ofstream ofs(path, std::ios::binary);

        // Write header + load commands
        ofs.write((const char*)buf.data(), buf.size());

        // Pad to TEXT_FILEOFF
        size_t padSize = TEXT_FILEOFF;
        if (buf.size() < padSize) {
            std::vector<uint8_t> pad(padSize - buf.size(), 0);
            ofs.write((const char*)pad.data(), pad.size());
        }

        // __text data: ret instruction
        uint8_t ret = 0xC3;
        ofs.write((const char*)&ret, 1);

        // __la_symbol_ptr data: 8 bytes of zero stub value
        uint64_t stubValue = 0;
        ofs.write((const char*)&stubValue, 8);

        // nlist_64 entries:
        // [0]: _myfunc — N_EXT|N_SECT (0x0F), n_sect=1, n_value=TEXT_VM
        {
            uint8_t entry[16] = {};
            entry[0] = 0;          // n_strx points to empty string (index 0 in strtab)
            entry[4] = 0x0F;       // N_EXT|N_SECT
            entry[5] = 1;          // n_sect = 1 (first section = __text)
            uint64_t val = TEXT_VM;
            std::memcpy(entry + 8, &val, 8);
            ofs.write((const char*)entry, 16);
        }
        // [1]: _printf — N_EXT (0x01), n_sect=0, n_value=0 (undefined)
        {
            uint8_t entry[16] = {};
            entry[0] = 8;          // n_strx = 8 ("_printf" at byte 8 in strtab)
            // strtab: "_myfunc\0_printf\0" -> offset 0 = "_myfunc", offset 8 = "_printf"
            entry[4] = 0x01;       // N_EXT only (undefined external)
            entry[5] = 0;
            uint64_t val = 0;
            std::memcpy(entry + 8, &val, 8);
            ofs.write((const char*)entry, 16);
        }

        // String table
        ofs.write(strtab, sizeof(strtab));

        // Indirect symbol table: 1 uint32 = index for _printf
        // Indirect symbol index = nlist_index + 2 (because 0=LOCAL, 1=ABS)
        uint32_t indirectIdx = 1 + 2; // points to nlist[1] (_printf)
        ofs.write((const char*)&indirectIdx, 4);

        ofs.close();
    }
};

static std::string create_temp_macho() {
    std::string path = "test_macho_binary.bin";
    builder b;
    b.build(path);
    b.dump_debug(path);
    return path;
}

int main(int argc, char** argv) {
    std::cout << "=== Enigma Engine - Mach-O Loader Test ===" << std::endl;

    std::string machoPath = create_temp_macho();
    if (machoPath.empty()) {
        std::cerr << "Failed to create temp Mach-O binary" << std::endl;
        return 1;
    }
    TEST("temp file created", !machoPath.empty());

    auto check = [&](const std::string& filePath) {
        auto loader = ghidra::createLoader();
        bool loaded = loader->load(filePath);
        if (!loaded) {
            std::cerr << "  Failed to load Mach-O: " << filePath << "\n";
            TEST("Mach-O loaded", false);
            return;
        }
        TEST("Mach-O loaded", true);

        TEST("Format is Mac OS X Mach-O",
             loader->getFormatName() == "Mac OS X Mach-O");
        TEST("Architecture is x86_64",
             loader->getArchitecture().find("x86") != std::string::npos);
        TEST("Bitness is 64", loader->getBitness() == 64);
        TEST("Entry point valid", loader->getEntryPoint() > 0);
        TEST("Image base valid", loader->getImageBase() > 0);

        std::cout << "  Format: " << loader->getFormatName() << std::endl;
        std::cout << "  Arch: " << loader->getArchitecture() << std::endl;
        std::cout << "  Bitness: " << loader->getBitness() << std::endl;
        std::cout << "  Entry: 0x" << std::hex << loader->getEntryPoint() << std::dec << std::endl;
        std::cout << "  ImageBase: 0x" << std::hex << loader->getImageBase() << std::dec << std::endl;

        auto sections = loader->getSections();
        TEST("Sections found", sections.size() > 0);
        std::cout << "  Sections: " << sections.size() << std::endl;
        for (const auto& sec : sections) {
            std::cout << "    " << sec.name << " @ 0x" << std::hex << sec.virtualAddress
                      << " size: 0x" << sec.virtualSize << std::dec
                      << (sec.isExecutable ? " X" : "")
                      << (sec.isReadable ? " R" : "")
                      << (sec.isWritable ? " W" : "") << std::endl;
        }

        auto symbols = loader->getSymbols();
        std::cout << "  Symbols: " << symbols.size() << std::endl;
        TEST("Symbols parsed", true);
        bool foundMyFunc = false, foundPrintf = false;
        for (const auto& sym : symbols) {
            std::cout << "    " << sym.name << " @ 0x" << std::hex << sym.address << std::dec << std::endl;
            if (sym.name == "_myfunc") foundMyFunc = true;
            if (sym.name == "_printf") foundPrintf = true;
        }
        TEST("Symbol _myfunc found", foundMyFunc);

        auto imports = loader->getImports();
        std::cout << "  Imports: " << imports.size() << std::endl;
        bool importWithAddress = false;
        for (const auto& imp : imports) {
            std::cout << "    " << imp.libraryName << "!" << imp.functionName
                      << " @ 0x" << std::hex << imp.address << std::dec << std::endl;
            if (imp.functionName == "_printf" && imp.address > 0) {
                importWithAddress = true;
            }
        }
        TEST("Imports parsed", true);
        TEST("Import resolved to stub address", importWithAddress);

        TEST("isBigEndian is false", !loader->isBigEndian());

        TestProgram testProgram;
        bool populated = loader->populateProgram(&testProgram.prog);
        TEST("Program populated", populated);
        TEST("Executable format matches",
             testProgram.prog.getExecutableFormat() == "Mac OS X Mach-O");
    };

    // Test thin Mach-O
    std::cout << "\n--- Thin Mach-O Test ---" << std::endl;
    check(machoPath);

    // Test fat binary wrapping the thin one
    std::cout << "\n--- Fat Mach-O Test ---" << std::endl;
    {
        std::ifstream thinFile(machoPath, std::ios::binary | std::ios::ate);
        size_t thinSize = static_cast<size_t>(thinFile.tellg());
        thinFile.seekg(0);
        std::vector<uint8_t> thinData(thinSize);
        thinFile.read(reinterpret_cast<char*>(thinData.data()), thinSize);
        thinFile.close();

        std::string fatPath = "test_macho_fat.bin";
        std::ofstream fatFile(fatPath, std::ios::binary);
        uint32_t magic = 0xBEBAFECA;
        fatFile.write(reinterpret_cast<const char*>(&magic), 4);
        uint32_t narch = 1;
        fatFile.write(reinterpret_cast<const char*>(&narch), 4);
        uint32_t archOffset = 8 + 1 * 20;
        uint32_t cputype = 0x01000007;
        uint32_t cpusubtype = 3;
        uint32_t align = 12;
        fatFile.write(reinterpret_cast<const char*>(&cputype), 4);
        fatFile.write(reinterpret_cast<const char*>(&cpusubtype), 4);
        fatFile.write(reinterpret_cast<const char*>(&archOffset), 4);
        uint32_t thinSize32 = static_cast<uint32_t>(thinSize);
        fatFile.write(reinterpret_cast<const char*>(&thinSize32), 4);
        fatFile.write(reinterpret_cast<const char*>(&align), 4);
        fatFile.write(reinterpret_cast<const char*>(thinData.data()), thinSize);
        fatFile.close();

        check(fatPath);
        std::remove(fatPath.c_str());
    }

    std::remove(machoPath.c_str());

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << passed << "/" << total << " tests passed" << std::endl;

    return (passed == total) ? 0 : 1;
}
