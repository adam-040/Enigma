/**
 * Enigma Engine - Golang Pipeline Test
 * Validates Task 3.1: GoBuildInfo and Go RTTI parsing.
 * Covers:
 *   - GoBuildInfoParser: magic header detection, version extraction
 *   - GoRttiParser: type record parsing, kind name mapping
 *   - Go type data type creation
 */
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

#include "ghidra/GoBuildInfoParser.h"
#include "ghidra/GoRttiParser.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/ProgramAddressFactory.h"
#include "ghidra/Memory.h"
#include "ghidra/TaskMonitor.h"
#include "ghidra/Language.h"
#include "ghidra/StandAloneDataTypeManager.h"

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
          prog("golang_test", nullptr, nullptr) {
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

// Build a synthetic Go build info section
static std::vector<uint8_t> buildGoBuildInfo() {
    std::vector<uint8_t> data(256, 0);

    // "\xff Go buildinf:" magic
    data[0] = 0xFF;
    data[1] = ' ';
    data[2] = 'G'; data[3] = 'o'; data[4] = ' ';
    data[5] = 'b'; data[6] = 'u'; data[7] = 'i'; data[8] = 'l';
    data[9] = 'd'; data[10] = 'i'; data[11] = 'n'; data[12] = 'f';
    data[13] = ':';
    // 2 pad bytes
    data[14] = 0; data[15] = 0;

    // Pointers to strings (offsets within the section)
    uint64_t verOff = 0x80;
    uint64_t modOff = 0xA0;
    uint64_t cmdOff = 0xC0;

    // Write pointers at offset 16
    memcpy(&data[16], &verOff, 8);
    memcpy(&data[24], &modOff, 8);
    memcpy(&data[32], &cmdOff, 8);

    // Go version string at offset 0x80
    const char* ver = "go1.21.0";
    memcpy(&data[verOff], ver, strlen(ver));

    // Module path at offset 0xA0
    const char* mod = "github.com/example/test";
    memcpy(&data[modOff], mod, strlen(mod));

    return data;
}

int main() {
    // === Test 1: GoBuildInfoParser ===
    {
        TestProgram tprog;
        Memory* memory = tprog.prog.getMemory();
        DefaultMemory* defaultMem = dynamic_cast<DefaultMemory*>(memory);
        TEST("memory is DefaultMemory", defaultMem != nullptr);

        std::vector<uint8_t> buildInfo = buildGoBuildInfo();
        Address start = tprog.addr(0x1000);
        DefaultMemoryBlock* block = defaultMem->createInitializedBlock(
            "go.buildinfo", start, buildInfo.size());
        TEST("buildinfo block created", block != nullptr);
        if (block) {
            block->setRead(true);
            block->putBytes(start, buildInfo.data(), static_cast<int>(buildInfo.size()));
        }

        GoBuildInfoParser::BuildInfo info = GoBuildInfoParser::parse(
            memory, start, static_cast<int64_t>(buildInfo.size()));
        TEST("GoBuildInfo parsed", info.valid);
        TEST("Go version extracted", info.goVersion == "go1.21.0");
        TEST("Module path extracted", info.modulePath == "github.com/example/test");
    }

    // === Test 2: GoBuildInfoParser findAndParse ===
    {
        TestProgram tprog;
        Memory* memory = tprog.prog.getMemory();
        DefaultMemory* defaultMem = dynamic_cast<DefaultMemory*>(memory);
        std::vector<uint8_t> buildInfo = buildGoBuildInfo();
        Address start = tprog.addr(0x2000);
        DefaultMemoryBlock* block = defaultMem->createInitializedBlock(
            "go_buildinfo", start, buildInfo.size());
        if (block) {
            block->setRead(true);
            block->putBytes(start, buildInfo.data(), static_cast<int>(buildInfo.size()));
        }

        GoBuildInfoParser::BuildInfo info = GoBuildInfoParser::findAndParse(memory);
        TEST("findAndParse found buildinfo", info.valid);
    }

    // === Test 3: GoRttiParser kind names ===
    {
        TEST("kind BOOL name", GoRttiParser::getKindName(1) == "bool");
        TEST("kind INT name", GoRttiParser::getKindName(2) == "int");
        TEST("kind INT64 name", GoRttiParser::getKindName(6) == "int64");
        TEST("kind UINT64 name", GoRttiParser::getKindName(11) == "uint64");
        TEST("kind STRUCT name", GoRttiParser::getKindName(18) == "struct");
        TEST("kind POINTER name", GoRttiParser::getKindName(22) == "pointer");
        TEST("kind STRING name", GoRttiParser::getKindName(23) == "string");
    }

    // === Test 4: GoRttiParser type parsing ===
    {
        TestProgram tprog;
        Memory* memory = tprog.prog.getMemory();
        DefaultMemory* defaultMem = dynamic_cast<DefaultMemory*>(memory);

        // Build a synthetic type record (Go 1.21 64-bit layout)
        std::vector<uint8_t> typeData(64, 0);
        // size = 16
        uint64_t size16 = 16;
        memcpy(&typeData[0], &size16, 8);
        // hash = 0x12345678
        uint32_t hash = 0x12345678;
        memcpy(&typeData[8], &hash, 4);
        // kind = 18 (struct)
        typeData[15] = 18;

        Address start = tprog.addr(0x3000);
        DefaultMemoryBlock* block = defaultMem->createInitializedBlock(
            ".gopclntab", start, typeData.size());
        if (block) {
            block->setRead(true);
            block->putBytes(start, typeData.data(), static_cast<int>(typeData.size()));
        }

        auto types = GoRttiParser::parseTypes(memory, start,
            static_cast<int64_t>(typeData.size()), true);
        TEST("GoRttiParser found types", !types.empty());

        if (!types.empty()) {
            auto& gt = types.begin()->second;
            TEST("type kind is struct", gt.kind == 18);
            TEST("type size is 16", gt.size == 16);
            TEST("type hash matches", gt.hash == 0x12345678);
            TEST("type name is struct", gt.name == "struct");
        }
    }

    // === Test 5: GoRttiParser createDataTypes ===
    {
        StandAloneDataTypeManager dtm("go_types_test");
        std::unordered_map<uint64_t, GoRttiParser::GoType> types;
        GoRttiParser::GoType gt;
        gt.address = 0x1000;
        gt.kind = 18;
        gt.size = 32;
        gt.hash = 0xDEADBEEF;
        gt.name = "struct";
        gt.valid = true;
        types[0x1000] = gt;

        GoRttiParser::createDataTypes(types, &dtm);
        int typeCount = dtm.getDataTypes().size();
        TEST("createDataTypes added Go types", typeCount > 0);
    }

    std::cout << "Golang Pipeline Tests: " << passed << "/" << total << " passed.\n" << std::flush;
    return (passed == total) ? 0 : 1;
}
