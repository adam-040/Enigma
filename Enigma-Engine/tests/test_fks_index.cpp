// test_fks_index — FksIndexManager rebuild, lookup, and clear

#include <ghidra/FksLibrary.h>
#include <ghidra/storage/FksIndexManager.h>
#include <iostream>
#include <filesystem>
#include <cassert>
#include <cstdlib>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"PASS: "<<n<<"\n";passed++;} \
  else{std::cout<<"FAIL: "<<n<<"\n";} } while(0)

namespace fs = std::filesystem;

static std::string getTestDir() {
    std::string base = std::getenv("TEMP") ? std::getenv("TEMP") : ".";
    return base + "/fks_index_test_dir";
}

int main() {
    using namespace ghidra;
    using namespace ghidra::storage;

    std::string testDir = getTestDir();
    fs::create_directories(testDir);

    // Build a library with 2 functions (different hashes)
    FksLibrary lib;
    FksLibraryMeta meta;
    meta.family      = "testlib";
    meta.version     = "1.0";
    meta.variant     = "release";
    meta.compiler    = "testcc";
    meta.language    = "x86:LE:64:default";
    meta.description = "index test library";
    meta.created     = 1700000000;
    lib.setMeta(meta);

    FksFunction f1;
    f1.uid         = 2001;
    f1.name        = "alpha";
    f1.nameDemangled = "alpha()";
    f1.hashes.fullHash  = 0xAAAABBBBCCCCDDDD;
    f1.hashes.shortHash = 0x1111222233334444;
    f1.hashes.mnemHash  = 0x5555666677778888;
    f1.hashes.callHash  = 0x9999AAAABBBBCCCC;
    f1.bodySize    = 128;
    f1.instrCount  = 20;
    f1.callCount   = 3;
    f1.basicBlocks = 4;
    f1.cyclomatic   = 2;
    f1.hasFrame    = true;
    f1.exported    = true;
    lib.addFunction(f1);

    FksFunction f2;
    f2.uid         = 2002;
    f2.name        = "beta";
    f2.nameDemangled = "beta(int)";
    f2.hashes.fullHash  = 0xDDDDCCCCBBBBAAAA;
    f2.hashes.shortHash = 0x4444333322221111;
    f2.hashes.mnemHash  = 0x8888777766665555;
    f2.hashes.callHash  = 0xCCCCBBBBAAAA9999;
    f2.bodySize    = 256;
    f2.instrCount  = 40;
    f2.callCount   = 7;
    f2.basicBlocks = 10;
    f2.cyclomatic   = 6;
    f2.hasFrame    = true;
    f2.exported    = false;
    lib.addFunction(f2);

    // === Test 1: save .fkslib into test dir ===
    std::string libPath = testDir + "/testlib.fkslib";
    bool saved = lib.saveToFile(libPath);
    TEST("save .fkslib to test dir", saved);
    TEST(".fkslib file exists", fs::exists(libPath));

    // === Test 2: rebuildFromFksDir ===
    int rebuilt = FksIndexManager::rebuildFromFksDir(testDir);
    TEST("rebuildFromFksDir returns > 0 functions", rebuilt > 0);

    // === Test 3: indexExists ===
    TEST("indexExists returns true after rebuild", FksIndexManager::indexExists(testDir) == true);

    // === Test 4: lookup fullHash for f1 — should return non-empty ===
    std::vector<uint8_t> result1 = FksIndexManager::lookupByFullHash(testDir, 0xAAAABBBBCCCCDDDD);
    TEST("lookupByFullHash for f1 is non-empty", !result1.empty());

    // === Test 5: lookup fullHash for f2 — should return non-empty ===
    std::vector<uint8_t> result2 = FksIndexManager::lookupByFullHash(testDir, 0xDDDDCCCCBBBBAAAA);
    TEST("lookupByFullHash for f2 is non-empty", !result2.empty());

    // === Test 6: lookup shortHash for f1 ===
    std::vector<uint8_t> shortResult = FksIndexManager::lookupByShortHash(testDir, 0x1111222233334444);
    TEST("lookupByShortHash for f1 is non-empty", !shortResult.empty());

    // === Test 7: lookup mnemHash for f1 ===
    std::vector<uint8_t> mnemResult = FksIndexManager::lookupByMnemHash(testDir, 0x5555666677778888);
    TEST("lookupByMnemHash for f1 is non-empty", !mnemResult.empty());

    // === Test 8: lookup callHash for f1 ===
    std::vector<uint8_t> callResult = FksIndexManager::lookupByCallHash(testDir, 0x9999AAAABBBBCCCC);
    TEST("lookupByCallHash for f1 is non-empty", !callResult.empty());

    // === Test 9: lookup hash that doesn't exist — should return empty ===
    std::vector<uint8_t> noResult = FksIndexManager::lookupByFullHash(testDir, 0xDEADBEEFCAFEBABE);
    TEST("lookupByFullHash for non-existent hash is empty", noResult.empty());

    // === Test 10: lookup by generic prefix for f1 fullHash ===
    std::vector<uint8_t> prefixResult = FksIndexManager::lookupByHash(
        testDir, FksIndexManager::PREFIX_FULL_HASH, 0xAAAABBBBCCCCDDDD);
    TEST("lookupByHash with PREFIX_FULL_HASH is non-empty", !prefixResult.empty());

    // === Test 11: clear index ===
    bool cleared = FksIndexManager::clear(testDir);
    TEST("clear returns true", cleared);
    TEST("lookup empty after clear", FksIndexManager::lookupByFullHash(testDir, 0xAAAABBBBCCCCDDDD).empty());

    // === Test 12: lookup after clear should be empty ===
    std::vector<uint8_t> afterClear = FksIndexManager::lookupByFullHash(testDir, 0xAAAABBBBCCCCDDDD);
    TEST("lookupByFullHash after clear is empty", afterClear.empty());

    // === Test 13: rebuild again after clear ===
    int rebuilt2 = FksIndexManager::rebuildFromFksDir(testDir);
    TEST("rebuildFromFksDir again returns > 0", rebuilt2 > 0);
    TEST("indexExists after second rebuild", FksIndexManager::indexExists(testDir) == true);
    std::vector<uint8_t> afterRebuild = FksIndexManager::lookupByFullHash(testDir, 0xAAAABBBBCCCCDDDD);
    TEST("lookupByFullHash after rebuild is non-empty", !afterRebuild.empty());

    // Cleanup
    fs::remove_all(testDir);

    std::cout << "\n=== FKS Index Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";

    return (passed == total) ? 0 : 1;
}
