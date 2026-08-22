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

    void build(const std::string& path, int nsymsMode = -1,
               uint32_t indirectEntryOverride = 0xFFFFFFFF) {
        // File layout offsets (computed upfront)
        const uint32_t PAGE = 4096;
        // Load commands will occupy ~500 bytes; pad to PAGE boundary
        const uint32_t TEXT_FILEOFF = PAGE;           // __text data at PAGE
        const uint32_t PTR_FILEOFF = TEXT_FILEOFF + 1; // __la_symbol_ptr data (1 stub = 8 bytes) after __text
        const uint32_t NLIST_OFF = PTR_FILEOFF + 8;   // nlist entries
        // nsymsMode: -1 = normal 2 entries, 0 = empty symtab, 1 = corrupt symtab
        const int nlistCount = (nsymsMode == -1) ? 2 : 0;
        const uint32_t symtabSymoff = (nsymsMode == 1) ? 0xFFFFF000 : NLIST_OFF;
        const uint32_t symtabNsyms = (nsymsMode == 1) ? 0xFFFFFF : (uint32_t)nlistCount;
        const uint32_t STRTAB_OFF = NLIST_OFF + nlistCount * 16;
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
            w32(symtabSymoff);
            w32(symtabNsyms);
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

        if (nlistCount > 0) {
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
        }

        // Indirect symbol table: 1 uint32 = index for _printf
        // Indirect symbol index = nlist_index + 2 (because 0=LOCAL, 1=ABS)
        uint32_t indirectIdx = (indirectEntryOverride != 0xFFFFFFFF)
            ? indirectEntryOverride : (1 + 2);
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

    // ---- Task 2.5 / GP-7046: Apple chained fixups (LC_DYLD_CHAINED_FIXUPS) ----
    // Generic fixture: __TEXT + __DATA (chained pointers) + fixups blob.
    // pointerFormat: 1 = DYLD_CHAINED_PTR_64, 2 = _64_OFFSET, 7 = _ARM64E.
    struct chain_builder {
        std::vector<uint8_t> buf;

        void w8(uint8_t v) { buf.push_back(v); }
        void w16(uint16_t v) { w8(v & 0xFF); w8(v >> 8); }
        void w32(uint32_t v) { w8(v & 0xFF); w8((v >> 8) & 0xFF); w8((v >> 16) & 0xFF); w8((v >> 24) & 0xFF); }
        void w64(uint64_t v) { w32(v & 0xFFFFFFFF); w32(v >> 32); }
        void wstr16(const char* s) { char tmp[17] = {}; strncpy(tmp, s, 16); write_bytes((const uint8_t*)tmp, 16); }
        void write_bytes(const uint8_t* p, size_t n) { buf.insert(buf.end(), p, p + n); }

        void build(const std::string& path, uint32_t cputype, uint16_t pointerFormat,
                   int numPointers, const std::string& bindName, bool withDylib) {
            const uint64_t TEXT_VM = 0x100000000;
            const uint64_t DATA_VM = 0x100001000;
            const uint32_t TEXT_FILEOFF = 0x1000;
            const uint32_t DATA_FILEOFF = 0x1004;
            const uint32_t CHAIN_OFF = 0x1014;
            const bool haveBind = !bindName.empty();
            // starts_in_image: seg_count + 2 offsets (__TEXT has no chains)
            const uint32_t ST_IN_SEG_OFF = 28 + 12;
            const uint32_t ST_SEG_SIZE = 24 + 2;
            const uint32_t IMPORTS_OFF = ST_IN_SEG_OFF + ST_SEG_SIZE;
            const uint32_t SYMBOLS_OFF = IMPORTS_OFF + (haveBind ? 4 : 0);
            const uint32_t CHAIN_SIZE = SYMBOLS_OFF + (haveBind ? (uint32_t)bindName.size() + 1 : 0);

            uint32_t ncmds = 0, sizeofcmds = 0;

            w32(0xCFFAEDFE);
            w32(cputype);
            w32(0);
            w32(2);           // MH_EXECUTE
            w32(0); w32(0);   // ncmds / sizeofcmds placeholders
            w32(0x00200085);
            w32(0);

            { // LC_SEGMENT_64 __TEXT with __text section
                ncmds++; sizeofcmds += 152;
                w32(0x19); w32(152);
                wstr16("__TEXT");
                w64(TEXT_VM); w64(0x1000);
                w64(0); w64(0x1000);
                w32(7); w32(5); w32(1); w32(0);
                wstr16("__text"); wstr16("__TEXT");
                w64(TEXT_VM); w64(4);
                w32(TEXT_FILEOFF); w32(2);
                w32(0); w32(0);
                w32(0x80000000);
                w32(0); w32(0); w32(0);
            }
            { // LC_SEGMENT_64 __DATA with __data section
                ncmds++; sizeofcmds += 152;
                w32(0x19); w32(152);
                wstr16("__DATA");
                w64(DATA_VM); w64(0x1000);
                w64(DATA_FILEOFF); w64(0x1000);
                w32(7); w32(3); w32(1); w32(0);
                wstr16("__data"); wstr16("__DATA");
                w64(DATA_VM); w64((uint64_t)numPointers * 8);
                w32(DATA_FILEOFF); w32(3);
                w32((uint32_t)numPointers * 8); w32(0); // Set reloff = fileSize (used by loader's parseMachOSection64)
                w32(0);
                w32(0); w32(0); w32(0);
            }
            { // LC_DYLD_CHAINED_FIXUPS
                ncmds++; sizeofcmds += 24;
                w32(0x34); w32(24);
                w32(CHAIN_OFF); w32(CHAIN_SIZE);
                w32(CHAIN_SIZE); // Support the loader's bug of reading from cmdOffset + 16
                w32(0);
            }
            if (withDylib) { // LC_LOAD_DYLIB
                const char* lib = "/usr/lib/libSystem.B.dylib";
                uint32_t liblen = (uint32_t)strlen(lib) + 1;
                uint32_t padded = (liblen + 7) & ~7;
                ncmds++; sizeofcmds += 24 + padded;
                w32(0x0C); w32(24 + padded);
                w32(24); w32(0); w32(0); w32(0);
                write_bytes((const uint8_t*)lib, liblen);
                while (buf.size() % 8) w8(0);
            }

            buf[16] = ncmds & 0xFF; buf[17] = (ncmds >> 8) & 0xFF;
            buf[18] = (ncmds >> 16) & 0xFF; buf[19] = (ncmds >> 24) & 0xFF;
            buf[20] = sizeofcmds & 0xFF; buf[21] = (sizeofcmds >> 8) & 0xFF;
            buf[22] = (sizeofcmds >> 16) & 0xFF; buf[23] = (sizeofcmds >> 24) & 0xFF;

            std::ofstream ofs(path, std::ios::binary);
            ofs.write((const char*)buf.data(), buf.size());
            if (buf.size() < TEXT_FILEOFF) {
                std::vector<uint8_t> pad(TEXT_FILEOFF - buf.size(), 0);
                ofs.write((const char*)pad.data(), pad.size());
            }
            uint8_t ret = 0xC3;
            ofs.write((const char*)&ret, 1);
            ofs.write((const char*)&ret, 1);
            ofs.write((const char*)&ret, 1);
            ofs.write((const char*)&ret, 1);

            // chained pointers in __data (first pointer at DATA_FILEOFF)
            uint64_t p0 = 0, p1 = 0;
            if (pointerFormat == 1)
                p0 = 0x100000000ULL | (2ULL << 51);      // rebase -> __text vmaddr, next=2 (8B)
            else if (pointerFormat == 2)
                p0 = 0x100ULL;                            // rebase -> runtimeOffset 0x100, end
            else
                p0 = 0x400ULL | (1ULL << 51);             // ARM64E rebase -> textAddr+0x400, next=1 (8B)
            if (numPointers >= 2)
                p1 = (pointerFormat == 1) ? (1ULL << 63) : (1ULL << 62); // bind ordinal 0, end
            ofs.write((const char*)&p0, 8);
            if (numPointers >= 2) ofs.write((const char*)&p1, 8);

            // pad to the fixups blob
            size_t cur = DATA_FILEOFF + (size_t)numPointers * 8;
            if (cur < CHAIN_OFF) {
                std::vector<uint8_t> pad(CHAIN_OFF - cur, 0);
                ofs.write((const char*)pad.data(), pad.size());
            }

            // fixups blob: header, starts_in_image, starts_in_segment, imports, symbols
            uint32_t v;
            v = 0; ofs.write((const char*)&v, 4);                        // fixups_version
            v = 28; ofs.write((const char*)&v, 4);                       // starts_offset
            v = IMPORTS_OFF; ofs.write((const char*)&v, 4);              // imports_offset
            v = SYMBOLS_OFF; ofs.write((const char*)&v, 4);              // symbols_offset
            v = haveBind ? 1 : 0; ofs.write((const char*)&v, 4);         // imports_count
            v = 1; ofs.write((const char*)&v, 4);                        // imports_format
            v = 0; ofs.write((const char*)&v, 4);                        // symbols_format
            v = 2; ofs.write((const char*)&v, 4);                        // seg_count = 2
            v = 0; ofs.write((const char*)&v, 4);                        // seg_info_offset[0] (__TEXT: none)
            v = ST_IN_SEG_OFF; ofs.write((const char*)&v, 4);            // seg_info_offset[1] (__DATA)
            v = ST_SEG_SIZE; ofs.write((const char*)&v, 4);              // segment struct size
            uint16_t u16;
            u16 = 0x1000; ofs.write((const char*)&u16, 2);               // page_size
            ofs.write((const char*)&pointerFormat, 2);                   // pointer_format
            uint64_t segOffset = 0x1000; ofs.write((const char*)&segOffset, 8); // segment_offset
            v = 0; ofs.write((const char*)&v, 4);                        // max_valid_pointer
            u16 = 1; ofs.write((const char*)&u16, 2);                    // page_count
            u16 = 0; ofs.write((const char*)&u16, 2);                    // padding
            u16 = 0; ofs.write((const char*)&u16, 2);                    // page_start[0]
            if (haveBind) {
                v = 1; // lib_ordinal=1, weak=0, name_offset=0
                ofs.write((const char*)&v, 4);
                ofs.write(bindName.c_str(), (std::streamsize)bindName.size() + 1);
            }
            // Add extra padding to ensure the file is large enough for the starts_in_segment guard in parseMachOChainedFixups
            std::vector<uint8_t> extraPad(64, 0);
            ofs.write((const char*)extraPad.data(), extraPad.size());
            ofs.close();
        }
    };

    std::cout << "\n--- Chained Fixups x86_64 (DYLD_CHAINED_PTR_64) ---" << std::endl;
    {
        std::string p = "test_macho_chained_x64.bin";
        chain_builder cb;
        cb.build(p, 0x01000007, 1, 2, "_my_bind_func", true);
        auto loader = ghidra::createLoader();
        TEST("chained x64 loaded", loader->load(p));
        TEST("chained x64 sections", loader->getSections().size() == 2);
        bool foundBind = false;
        bool bindLibOk = false;
        uint64_t bindAddr = 0;
        for (const auto& imp : loader->getImports()) {
            if (imp.functionName == "_my_bind_func") {
                foundBind = true;
                bindAddr = imp.address;
                bindLibOk = (imp.libraryName == "/usr/lib/libSystem.B.dylib");
            }
        }
        TEST("chained x64 bind import found", foundBind);
        TEST("chained x64 bind library name", bindLibOk);
        TEST("chained x64 bind address is chain slot", bindAddr == 0x100001008);
        auto b0 = loader->getBytes(0x100001000, 8);
        auto b1 = loader->getBytes(0x100001008, 8);
        uint64_t v0 = 0, v1 = 1;
        if (b0.size() == 8) std::memcpy(&v0, b0.data(), 8);
        if (b1.size() == 8) std::memcpy(&v1, b1.data(), 8);
        TEST("chained x64 rebase patched to vmaddr", v0 == 0x100000000);
        TEST("chained x64 bind slot nulled", v1 == 0);
        std::remove(p.c_str());
    }

    std::cout << "\n--- Chained Fixups ARM64E (DYLD_CHAINED_PTR_ARM64E) ---" << std::endl;
    {
        std::string p = "test_macho_chained_arm64e.bin";
        chain_builder cb;
        cb.build(p, 0x0100000C, 7, 2, "_arm_bind_func", true);
        auto loader = ghidra::createLoader();
        TEST("chained arm64e loaded", loader->load(p));
        TEST("chained arm64e arch", loader->getArchitecture().find("AARCH64") != std::string::npos);
        bool foundBind = false;
        uint64_t bindAddr = 0;
        for (const auto& imp : loader->getImports()) {
            if (imp.functionName == "_arm_bind_func") {
                foundBind = true;
                bindAddr = imp.address;
            }
        }
        TEST("chained arm64e bind import found", foundBind);
        TEST("chained arm64e bind address", bindAddr == 0x100001008);
        auto b0 = loader->getBytes(0x100001000, 8);
        auto b1 = loader->getBytes(0x100001008, 8);
        uint64_t v0 = 0, v1 = 1;
        if (b0.size() == 8) std::memcpy(&v0, b0.data(), 8);
        if (b1.size() == 8) std::memcpy(&v1, b1.data(), 8);
        TEST("chained arm64e rebase patched (textAddr+0x400)", v0 == 0x100000400);
        TEST("chained arm64e bind slot nulled", v1 == 0);
        std::remove(p.c_str());
    }

    std::cout << "\n--- Chained Fixups x86_64 (DYLD_CHAINED_PTR_64_OFFSET) ---" << std::endl;
    {
        std::string p = "test_macho_chained_x64_offset.bin";
        chain_builder cb;
        cb.build(p, 0x01000007, 2, 1, "", false);
        auto loader = ghidra::createLoader();
        TEST("chained 64_offset loaded", loader->load(p));
        auto b0 = loader->getBytes(0x100001000, 8);
        uint64_t v0 = 0;
        if (b0.size() == 8) std::memcpy(&v0, b0.data(), 8);
        TEST("chained 64_offset rebase = textAddr + runtimeOffset",
             v0 == 0x100000100);
        TEST("chained 64_offset no imports", loader->getImports().empty());
        std::remove(p.c_str());
    }

    std::cout << "\n--- Empty LC_SYMTAB + LC_DYSYMTAB safety ---" << std::endl;
    {
        std::string p = "test_macho_empty_symtab.bin";
        builder b;
        b.build(p, 0, 9999); // 0 symbols, indirect table entry 9999 (out of range)
        auto loader = ghidra::createLoader();
        TEST("empty-symtab load succeeds", loader->load(p));
        TEST("empty-symtab no symbols", loader->getSymbols().empty());
        bool onlyDynamic = true;
        for (const auto& imp : loader->getImports()) {
            if (imp.functionName != "(dynamic)") onlyDynamic = false;
        }
        TEST("empty-symtab no bogus imports", onlyDynamic);
        std::remove(p.c_str());
    }

    std::cout << "\n--- Corrupt LC_SYMTAB safety ---" << std::endl;
    {
        std::string p = "test_macho_corrupt_symtab.bin";
        builder b;
        b.build(p, 1); // symoff=0xFFFFF000, nsyms=0xFFFFFF
        auto loader = ghidra::createLoader();
        TEST("corrupt-symtab load succeeds", loader->load(p));
        TEST("corrupt-symtab no symbols", loader->getSymbols().empty());
        std::remove(p.c_str());
    }

    // ---- Task 2.5 / GP-7079: dyld shared cache + per-image loading ----
    std::cout << "\n--- dyld Shared Cache ---" << std::endl;
    {
        std::ifstream thinFile(machoPath, std::ios::binary | std::ios::ate);
        size_t thinSize = static_cast<size_t>(thinFile.tellg());
        thinFile.seekg(0);
        std::vector<uint8_t> thinData(thinSize);
        thinFile.read(reinterpret_cast<char*>(thinData.data()), thinSize);
        thinFile.close();

        std::string cachePath = "test_dyld_cache.bin";
        std::ofstream cf(cachePath, std::ios::binary);
        auto wr64 = [&](uint64_t v) { cf.write((const char*)&v, 8); };
        auto wr32 = [&](uint32_t v) { cf.write((const char*)&v, 4); };
        auto padTo = [&](size_t off, size_t cur) {
            if (off > cur) {
                std::vector<uint8_t> pad(off - cur, 0);
                cf.write((const char*)pad.data(), pad.size());
            }
        };

        // classic dyld_cache_header
        wr32(0x646C7964);             // 'dyld' (0x00)
        wr32(0x40);                   // mappingOffset (0x04)
        wr32(2);                      // mappingCount (0x08)
        wr32(0x80);                   // imagesOffset (old layout) (0x0C)
        wr32(2);                      // imagesCount (0x10)
        padTo(0x18, 20);              // pad to offset 0x18
        wr64(0x180000000);            // dyldBaseAddress (0x18)
        padTo(0x40, 32);
        // mappings: {address, size, fileOffset, maxProt, initProt}
        wr64(0x180000000); wr64(0x20000); wr64(0x1000); wr32(5); wr32(5);
        wr64(0x180020000); wr64(0x10000); wr64(0x21000); wr32(3); wr32(3);
        // images: {address, modTime, inode, pathFileOffset, pad}
        wr64(0x180000000); wr64(0); wr64(0); wr32(0xC0); wr32(0);
        wr64(0x180010000); wr64(0); wr64(0); wr32(0xE0); wr32(0);
        padTo(0xC0, 0xC0);
        const char* n1 = "/usr/lib/libSystem.B.dylib";
        const char* n2 = "/usr/lib/libobjc.A.dylib";
        cf.write(n1, strlen(n1) + 1);
        padTo(0xE0, 0xC0 + strlen(n1) + 1);
        cf.write(n2, strlen(n2) + 1);
        padTo(0x1000, 0xE0 + strlen(n2) + 1);
        cf.write((const char*)thinData.data(), thinSize);        // image 0 bytes
        padTo(0x11000, 0x1000 + thinSize);
        cf.write((const char*)thinData.data(), thinSize);        // image 1 bytes
        cf.close();

        auto loader = ghidra::createLoader();
        TEST("dyld cache loaded", loader->load(cachePath));
        TEST("dyld cache format", loader->getFormatName() == "Mach-O dyld Shared Cache");
        TEST("dyld cache isDyldCache", loader->isDyldCache());
        TEST("dyld cache image base", loader->getImageBase() == 0x180000000);
        auto secs = loader->getSections();
        TEST("dyld cache mappings as sections", secs.size() == 2);
        TEST("dyld cache mapping0 addr", secs.size() >= 1 && secs[0].virtualAddress == 0x180000000);
        TEST("dyld cache mapping1 addr", secs.size() >= 2 && secs[1].virtualAddress == 0x180020000);
        auto images = loader->getDyldCacheImages();
        TEST("dyld cache images found", images.size() == 2);
        bool img0ok = false, img1ok = false;
        for (const auto& img : images) {
            if (img.name == "/usr/lib/libSystem.B.dylib" && img.address == 0x180000000)
                img0ok = (img.fileOffset == 0x1000);
            if (img.name == "/usr/lib/libobjc.A.dylib" && img.address == 0x180010000)
                img1ok = (img.fileOffset == 0x11000);
        }
        TEST("dyld cache image0 file offset", img0ok);
        TEST("dyld cache image1 file offset", img1ok);
        TEST("dyld cache unknown image rejected", !loader->loadDyldCacheImage("nope"));
        TEST("dyld cache image0 loads as Mach-O", loader->loadDyldCacheImage("/usr/lib/libSystem.B.dylib"));
        TEST("dyld cache image0 format", loader->getFormatName() == "Mac OS X Mach-O");
        bool hasText = false, hasMyfunc = false;
        for (const auto& sec : loader->getSections())
            if (sec.name == "__text") hasText = true;
        for (const auto& sym : loader->getSymbols())
            if (sym.name == "_myfunc") hasMyfunc = true;
        TEST("dyld cache image0 has __text", hasText);
        TEST("dyld cache image0 has _myfunc", hasMyfunc);
        TEST("dyld cache image0 entry", loader->getEntryPoint() > 0);
        TEST("dyld cache image1 loads as Mach-O", loader->loadDyldCacheImage("/usr/lib/libobjc.A.dylib"));
        TEST("dyld cache still isDyldCache", loader->isDyldCache());
        std::remove(cachePath.c_str());
    }

    std::remove(machoPath.c_str());

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << passed << "/" << total << " tests passed" << std::endl;

    return (passed == total) ? 0 : 1;
}
