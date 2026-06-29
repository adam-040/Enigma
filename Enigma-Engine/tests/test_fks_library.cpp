// test_fks_library — FksLibrary save/load roundtrip + loadFromBuffer

#include <ghidra/FksLibrary.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>
#include <cstring>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"PASS: "<<n<<"\n";passed++;} \
  else{std::cout<<"FAIL: "<<n<<"\n";} } while(0)

namespace fs = std::filesystem;

static std::string getTempPath() {
    std::string base = std::getenv("TEMP") ? std::getenv("TEMP") : ".";
    return base + "/fks_lib_test_output.fkslib";
}

int main() {
    using namespace ghidra;

    std::string tempPath = getTempPath();

    // Build a library with meta + 3 functions
    FksLibrary lib;
    FksLibraryMeta meta;
    meta.family      = "testlib";
    meta.version     = "1.0";
    meta.variant     = "debug";
    meta.compiler    = "gcc";
    meta.language    = "x86:LE:64:default";
    meta.description = "test library for roundtrip";
    meta.created     = 1700000000;
    lib.setMeta(meta);

    FksFunction f1;
    f1.uid         = 1001;
    f1.name        = "init_system";
    f1.nameDemangled = "init_system()";
    f1.hashes.fullHash  = 0xAABBCCDD11223344;
    f1.hashes.shortHash = 0x1122334455667788;
    f1.hashes.mnemHash  = 0x2233445566778899;
    f1.hashes.callHash  = 0x33445566778899AA;
    f1.bodySize    = 256;
    f1.instrCount  = 42;
    f1.callCount   = 5;
    f1.basicBlocks = 8;
    f1.cyclomatic   = 4;
    f1.hasFrame    = true;
    f1.exported    = true;
    lib.addFunction(f1);

    FksFunction f2;
    f2.uid         = 1002;
    f2.name        = "process_data";
    f2.nameDemangled = "process_data(void*)";
    f2.hashes.fullHash  = 0xBBCCDD0011223344;
    f2.hashes.shortHash = 0x2233445566778899;
    f2.hashes.mnemHash  = 0x3344556677889900;
    f2.hashes.callHash  = 0x4455667788990011;
    f2.bodySize    = 512;
    f2.instrCount  = 80;
    f2.callCount   = 12;
    f2.basicBlocks = 15;
    f2.cyclomatic   = 9;
    f2.hasFrame    = true;
    f2.exported    = false;
    lib.addFunction(f2);

    FksFunction f3;
    f3.uid         = 1003;
    f3.name        = "shutdown";
    f3.nameDemangled = "shutdown()";
    f3.hashes.fullHash  = 0xCCDD001122334455;
    f3.hashes.shortHash = 0x0011223344556677;
    f3.hashes.mnemHash  = 0;
    f3.hashes.callHash  = 0;
    f3.bodySize    = 64;
    f3.instrCount  = 10;
    f3.callCount   = 0;
    f3.basicBlocks = 2;
    f3.cyclomatic   = 1;
    f3.hasFrame    = false;
    f3.exported    = true;
    lib.addFunction(f3);

    // === Test 1: save to file ===
    bool saved = lib.saveToFile(tempPath);
    TEST("saveToFile returns true", saved);
    TEST("file exists after save", fs::exists(tempPath));

    // === Test 2: loadFromFile roundtrip ===
    auto loaded = FksLibrary::loadFromFile(tempPath);
    TEST("loadFromFile returns non-null", loaded != nullptr);

    if (loaded) {
        const auto& lm = loaded->getMeta();
        TEST("meta.family matches", lm.family == "testlib");
        TEST("meta.version matches", lm.version == "1.0");
        TEST("meta.variant matches", lm.variant == "debug");
        TEST("meta.compiler matches", lm.compiler == "gcc");
        TEST("meta.language matches", lm.language == "x86:LE:64:default");
        TEST("meta.description matches", lm.description == "test library for roundtrip");
        TEST("meta.created matches", lm.created == 1700000000);

        TEST("function count is 3", loaded->functionCount() == 3);

        const auto& funcs = loaded->getFunctions();
        if (funcs.size() == 3) {
            TEST("func[0] uid matches", funcs[0].uid == 1001);
            TEST("func[0] name matches", funcs[0].name == "init_system");
            TEST("func[0] fullHash matches", funcs[0].hashes.fullHash == 0xAABBCCDD11223344);
            TEST("func[0] shortHash matches", funcs[0].hashes.shortHash == 0x1122334455667788);
            TEST("func[0] bodySize matches", funcs[0].bodySize == 256);
            TEST("func[0] instrCount matches", funcs[0].instrCount == 42);
            TEST("func[0] hasFrame is true", funcs[0].hasFrame == true);
            TEST("func[0] exported is true", funcs[0].exported == true);

            TEST("func[1] uid matches", funcs[1].uid == 1002);
            TEST("func[1] name matches", funcs[1].name == "process_data");
            TEST("func[1] fullHash matches", funcs[1].hashes.fullHash == 0xBBCCDD0011223344);
            TEST("func[1] exported is false", funcs[1].exported == false);

            TEST("func[2] uid matches", funcs[2].uid == 1003);
            TEST("func[2] name matches", funcs[2].name == "shutdown");
            TEST("func[2] fullHash matches", funcs[2].hashes.fullHash == 0xCCDD001122334455);
            TEST("func[2] mnemHash is 0", funcs[2].hashes.mnemHash == 0);
        }
    }

    // === Test 3: loadFromBuffer roundtrip ===
    {
        std::ifstream ifs(tempPath, std::ios::binary | std::ios::ate);
        if (ifs.is_open()) {
            std::streamsize sz = ifs.tellg();
            ifs.seekg(0, std::ios::beg);
            std::vector<uint8_t> buf(static_cast<size_t>(sz));
            if (ifs.read(reinterpret_cast<char*>(buf.data()), sz)) {
                auto fromBuf = FksLibrary::loadFromBuffer(buf.data(), buf.size());
                TEST("loadFromBuffer returns non-null", fromBuf != nullptr);
                if (fromBuf) {
                    TEST("loadFromBuffer meta.family matches", fromBuf->getMeta().family == "testlib");
                    TEST("loadFromBuffer function count", fromBuf->functionCount() == 3);
                    const auto& bf = fromBuf->getFunctions();
                    if (bf.size() == 3) {
                        TEST("loadFromBuffer func[0] uid", bf[0].uid == 1001);
                        TEST("loadFromBuffer func[1] name", bf[1].name == "process_data");
                        TEST("loadFromBuffer func[2] exported", bf[2].exported == true);
                    }
                }
            } else {
                std::cout << "FAIL: could not read temp file into buffer\n";
                total++;
            }
        } else {
            std::cout << "FAIL: could not open temp file for buffer test\n";
            total++;
        }
    }

    // === Test 4: empty library roundtrip ===
    {
        std::string emptyPath = getTempPath() + ".empty";
        FksLibrary emptyLib;
        FksLibraryMeta emptyMeta;
        emptyMeta.family  = "empty";
        emptyMeta.version = "0.0";
        emptyLib.setMeta(emptyMeta);

        TEST("empty lib saveToFile", emptyLib.saveToFile(emptyPath));
        auto loadedEmpty = FksLibrary::loadFromFile(emptyPath);
        TEST("empty lib loadFromFile non-null", loadedEmpty != nullptr);
        if (loadedEmpty) {
            TEST("empty lib meta.family", loadedEmpty->getMeta().family == "empty");
            TEST("empty lib functionCount is 0", loadedEmpty->functionCount() == 0);
        }
        fs::remove(emptyPath);
    }

    // Cleanup
    fs::remove(tempPath);

    std::cout << "\n=== FKS Library Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";

    return (passed == total) ? 0 : 1;
}
