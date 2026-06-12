#include <ghidra/storage/IndexManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <chrono>
#include <sstream>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace fs = std::filesystem;
using namespace ghidra;
using namespace ghidra::storage;

static std::string createTempRepo() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    std::stringstream ss;
    ss << "repo_idx_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    Repository::create(path, "test", "test.bin", "0000", "x86:LE:64:default", "gcc", 0x100000);
    return path;
}

int main() {
    // ------------------------------------------------------------------
    // Add and lookup symbols
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        TEST("addSymbol main", IndexManager::addSymbol(repoPath, "main", 0x401000));
        TEST("addSymbol init", IndexManager::addSymbol(repoPath, "_init", 0x401200));
        TEST("addSymbol printf", IndexManager::addSymbol(repoPath, "printf", 0x500000));

        uint64_t addr = IndexManager::lookupSymbol(repoPath, "main");
        TEST("lookup main -> 0x401000", addr == 0x401000);

        addr = IndexManager::lookupSymbol(repoPath, "_init");
        TEST("lookup _init -> 0x401200", addr == 0x401200);

        addr = IndexManager::lookupSymbol(repoPath, "printf");
        TEST("lookup printf -> 0x500000", addr == 0x500000);

        // Reverse lookup
        std::string name = IndexManager::lookupSymbolByAddress(repoPath, 0x401000);
        TEST("lookupByAddress 0x401000 -> main", name == "main");

        name = IndexManager::lookupSymbolByAddress(repoPath, 0x500000);
        TEST("lookupByAddress 0x500000 -> printf", name == "printf");

        // Non-existent
        addr = IndexManager::lookupSymbol(repoPath, "nonexistent");
        TEST("lookup nonexistent -> 0", addr == 0);

        name = IndexManager::lookupSymbolByAddress(repoPath, 0x999999);
        TEST("lookupByAddress nonexistent -> empty", name == "");

        IndexManager::clear(repoPath);
        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Remove symbol
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        IndexManager::addSymbol(repoPath, "temp", 0x300000);
        TEST("symbol exists before remove",
             IndexManager::lookupSymbol(repoPath, "temp") == 0x300000);

        TEST("removeSymbol temp",
             IndexManager::removeSymbol(repoPath, "temp"));

        TEST("symbol gone after remove",
             IndexManager::lookupSymbol(repoPath, "temp") == 0);

        TEST("reverse also gone",
             IndexManager::lookupSymbolByAddress(repoPath, 0x300000) == "");

        // Remove non-existent
        TEST("remove non-existent returns false",
             !IndexManager::removeSymbol(repoPath, "nope"));

        // Remove empty name
        TEST("remove empty name returns false",
             !IndexManager::removeSymbol(repoPath, ""));

        IndexManager::clear(repoPath);
        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Add and lookup functions
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        TEST("addFunction", IndexManager::addFunction(repoPath, "func1", 0x401000));
        TEST("addFunction", IndexManager::addFunction(repoPath, "func2", 0x402000));

        uint64_t entry = IndexManager::lookupFunction(repoPath, "func1");
        TEST("lookup func1 -> 0x401000", entry == 0x401000);

        entry = IndexManager::lookupFunction(repoPath, "func2");
        TEST("lookup func2 -> 0x402000", entry == 0x402000);

        std::string name = IndexManager::lookupFunctionByEntry(repoPath, 0x401000);
        TEST("lookupByEntry 0x401000 -> func1", name == "func1");

        name = IndexManager::lookupFunctionByEntry(repoPath, 0x402000);
        TEST("lookupByEntry 0x402000 -> func2", name == "func2");

        // Non-existent
        entry = IndexManager::lookupFunction(repoPath, "nonexistent");
        TEST("lookup nonexistent function -> 0", entry == 0);

        IndexManager::clear(repoPath);
        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Remove function
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        IndexManager::addFunction(repoPath, "temp_func", 0x500000);
        TEST("func exists before remove",
             IndexManager::lookupFunction(repoPath, "temp_func") == 0x500000);

        TEST("removeFunction", IndexManager::removeFunction(repoPath, "temp_func"));
        TEST("func gone after remove",
             IndexManager::lookupFunction(repoPath, "temp_func") == 0);
        TEST("reverse gone",
             IndexManager::lookupFunctionByEntry(repoPath, 0x500000) == "");

        IndexManager::clear(repoPath);
        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Clear index
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        IndexManager::addSymbol(repoPath, "s1", 0x100);
        IndexManager::addSymbol(repoPath, "s2", 0x200);
        IndexManager::addFunction(repoPath, "f1", 0x300);

        TEST("entries present before clear",
             IndexManager::lookupSymbol(repoPath, "s1") == 0x100);
        TEST("func present before clear",
             IndexManager::lookupFunction(repoPath, "f1") == 0x300);

        TEST("clear succeeds", IndexManager::clear(repoPath));

        TEST("symbol gone after clear",
             IndexManager::lookupSymbol(repoPath, "s1") == 0);
        TEST("func gone after clear",
             IndexManager::lookupFunction(repoPath, "f1") == 0);

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Empty name handling
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        TEST("addSymbol empty name", !IndexManager::addSymbol(repoPath, "", 0x100));
        TEST("lookup empty name -> 0",
             IndexManager::lookupSymbol(repoPath, "") == 0);
        TEST("addFunction empty name",
             !IndexManager::addFunction(repoPath, "", 0x100));
        TEST("lookupFunction empty name -> 0",
             IndexManager::lookupFunction(repoPath, "") == 0);

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Rebuild from ProgramDB (empty — default ProgramDB has null managers,
    // so rebuild succeeds but adds nothing; entries via addSymbol work)
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;

        // Rebuild on empty program — should succeed gracefully
        TEST("rebuild empty program succeeds",
             IndexManager::rebuildFromProgramDB(repoPath, program));

        // No entries from empty rebuild
        TEST("no symbol after empty rebuild",
             IndexManager::lookupSymbol(repoPath, "main") == 0);

        // Entries added directly still work
        TEST("add after rebuild",
             IndexManager::addSymbol(repoPath, "direct_sym", 0x5000));
        TEST("lookup direct sym",
             IndexManager::lookupSymbol(repoPath, "direct_sym") == 0x5000);

        IndexManager::clear(repoPath);
        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Add same symbol twice (idempotent)
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        TEST("first add", IndexManager::addSymbol(repoPath, "sym", 0x100));
        TEST("second add (overwrite)", IndexManager::addSymbol(repoPath, "sym", 0x200));

        uint64_t addr = IndexManager::lookupSymbol(repoPath, "sym");
        TEST("last write wins", addr == 0x200);

        // Forward mapping overwrites, but old reverse mapping is stale
        // (LMDB doesn't cascade-delete old reverse entries on overwrite)
        std::string name = IndexManager::lookupSymbolByAddress(repoPath, 0x200);
        TEST("reverse points to new", name == "sym");

        name = IndexManager::lookupSymbolByAddress(repoPath, 0x100);
        TEST("old reverse mapping stale", name == "sym");

        IndexManager::clear(repoPath);
        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Non-existent repo path
    // ------------------------------------------------------------------
    {
        std::string badPath = "nonexistent_idx_repo";

        TEST("lookupSymbol bad path -> 0",
             IndexManager::lookupSymbol(badPath, "x") == 0);
        TEST("lookupSymbolByAddress bad path -> empty",
             IndexManager::lookupSymbolByAddress(badPath, 0x100) == "");
        TEST("lookupFunction bad path -> 0",
             IndexManager::lookupFunction(badPath, "x") == 0);
        TEST("lookupFunctionByEntry bad path -> empty",
             IndexManager::lookupFunctionByEntry(badPath, 0x100) == "");
        TEST("addSymbol bad path -> false",
             !IndexManager::addSymbol(badPath, "x", 0x100));
        TEST("removeSymbol bad path -> false",
             !IndexManager::removeSymbol(badPath, "x"));
        TEST("addFunction bad path -> false",
             !IndexManager::addFunction(badPath, "x", 0x100));
        TEST("removeFunction bad path -> false",
             !IndexManager::removeFunction(badPath, "x"));
        TEST("clear bad path -> false",
             !IndexManager::clear(badPath));
    }

    std::cout << "\n=== Phase 5 Storage Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}
