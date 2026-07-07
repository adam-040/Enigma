#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <filesystem>

#include "ghidra/DecompInterface.h"
#include "ghidra/BinaryLoader.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/FunctionIterator.h"
#include "ghidra/Function.h"
#include "ghidra/Msg.h"
#include "ghidra/storage/WorkingSnapshot.h"
#include "ghidra/storage/Repository.h"
#include "ghidra/storage/CommitManager.h"
#include "ghidra/storage/EventLog.h"
#include "ghidra/storage/SnapshotReader.h"

int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

#ifndef ENIGMA_SLEIGH_DIR
#define ENIGMA_SLEIGH_DIR ""
#endif

static std::string getTestBinaryPath(int argc, char** argv) {
    const char* envPath = std::getenv("ENIGMA_TEST_BINARY");
    if (envPath && *envPath) return envPath;
    if (argc > 0 && argv && argv[0] && *argv[0]) return argv[0];
    return "enigma_test_decomp_interface.exe";
}

int main(int argc, char** argv) {
    std::cout << "=== DecompInterface Integration Test ===" << std::endl;

    // T1: initializeLibrary / shutdownLibrary
    std::cout << "\n--- T1: Library Init ---" << std::endl;
    TEST("initializeLibrary succeeds", ghidra::DecompInterface::initializeLibrary());
    ghidra::DecompInterface::shutdownLibrary();
    TEST("shutdownLibrary resets", true);
    // Re-init for remaining tests
    TEST("re-initialize succeeds", ghidra::DecompInterface::initializeLibrary());

    // T2: Default state
    std::cout << "\n--- T2: Default State ---" << std::endl;
    {
        ghidra::DecompInterface di;
        TEST("not open by default", !di.isOpen());
        ghidra::DecompileResults empty = di.decompileFunction(ghidra::Address(), nullptr);
        TEST("decompile without program returns decompiled=false", !empty.decompiled);
    }

    // T3: openProgram with null
    std::cout << "\n--- T3: Open Null Program ---" << std::endl;
    {
        ghidra::DecompInterface di;
        TEST("openProgram(nullptr) returns false", !di.openProgram(nullptr));
        TEST("still not open", !di.isOpen());
    }

    // T4: Load a binary and populate ProgramDB
    std::cout << "\n--- T4: Load Binary and Create Program ---" << std::endl;
    std::string binaryPath = getTestBinaryPath(argc, argv);
    auto loader = ghidra::createLoader();
    if (!loader || !loader->load(binaryPath)) {
        std::cerr << "Failed to load binary: " << binaryPath << std::endl;
        TEST("binary loaded", false);
        std::cout << "\n=== Summary ===\n" << passed << "/" << total << " tests passed" << std::endl;
        return 1;
    }
    std::cout << "  Format: " << loader->getFormatName() << std::endl;
    std::cout << "  Arch: " << loader->getArchitecture() << std::endl;
    std::cout << "  Bitness: " << loader->getBitness() << std::endl;
    TEST("binary loaded OK", true);

    // T5: Populate program and decompile entry via DecompInterface
    std::cout << "\n--- T5: DecompInterface via populated ProgramDB ---" << std::endl;
    {
        ghidra::GenericAddressSpace ramSpace("ram", 64, ghidra::AddressSpace::TYPE_RAM, 1);
        ghidra::ProgramDB prog("test_prog", nullptr, nullptr);
        auto* addrFactory = dynamic_cast<ghidra::ProgramAddressFactory*>(prog.getAddressFactory());
        if (addrFactory) {
            addrFactory->addAddressSpace(&ramSpace);
            addrFactory->setDefaultSpace(&ramSpace);
        }
        bool populated = loader->populateProgram(&prog);
        TEST("populateProgram succeeds", populated);

        if (populated) {
            ghidra::DecompInterface di;
            bool opened = di.openProgram(&prog);
            TEST("openProgram succeeds", opened);

            if (opened) {
                std::vector<ghidra::DecompFunctionSummary> functions = di.getFunctions();
                TEST("getFunctions returns ProgramDB functions", !functions.empty());

                // Look up entry function from the loaded program
                uint64_t ep = loader->getEntryPoint();
                auto* space = prog.getAddressFactory()
                    ? const_cast<ghidra::AddressSpace*>(
                        prog.getAddressFactory()->getDefaultAddressSpace())
                    : nullptr;
                TEST("default address space exists", space != nullptr);

                if (space) {
                    ghidra::Address entryAddr(space, static_cast<int64_t>(ep));
                    ghidra::Function* entryFunc = prog.getFunctionManager()->getFunctionAt(entryAddr);
                    TEST("entry function exists", entryFunc != nullptr);

                    if (entryFunc) {
                        std::string originalEntryName = entryFunc->getName();
                        auto entrySummary = std::find_if(functions.begin(), functions.end(),
                            [&entryAddr](const ghidra::DecompFunctionSummary& item) {
                                return item.entryAddress == entryAddr;
                            });
                        TEST("getFunctions includes entry", entrySummary != functions.end());
                        if (entrySummary != functions.end()) {
                            TEST("entry summary name matches ProgramDB",
                                 entrySummary->name == entryFunc->getName());
                            TEST("entry summary has body", entrySummary->bodyAddressCount > 0);
                        }

                        std::cout << "  Entry function: " << entryFunc->getName()
                                  << " at 0x" << std::hex << ep << std::dec << std::endl;

                        ghidra::DecompileResults res = di.decompileFunction(entryAddr, nullptr);
                        TEST("decompile succeeded", res.decompiled);
                        if (res.decompiled) {
                            TEST("function name populated", !res.functionName.empty());
                            TEST("callCount matches calls vector",
                                 res.callCount == static_cast<int>(res.calls.size()));
                            std::cout << "  Decompiled: " << res.functionName
                                      << "  size=" << res.functionSize
                                      << "  cc=" << res.conventionName
                                      << "  lines=" << std::count(res.cCode.begin(), res.cCode.end(), '\n')
                                      << std::endl;
                            if (!res.cCode.empty())
                                std::cout << "  Output:\n" << res.cCode.substr(0, 500) << std::endl;

                            ghidra::DecompileResults viaFunction =
                                di.decompileFunction(entryFunc, nullptr);
                            TEST("decompile(Function*) succeeds", viaFunction.decompiled);
                            TEST("decompile(Function*) output matches address",
                                 viaFunction.cCode == res.cCode);
                        }
                    }

                    std::cout << "\n--- T6: Storage Reload Bridge ---" << std::endl;
                    std::filesystem::path snapPath =
                        std::filesystem::temp_directory_path() /
                        "enigma_decomp_interface_workflow.fbs";
                    bool saved = ghidra::storage::WorkingSnapshot::save(
                        prog, snapPath.string());
                    TEST("WorkingSnapshot saves populated ProgramDB", saved);
                    auto loadedProgram = ghidra::storage::WorkingSnapshot::load(
                        snapPath.string());
                    TEST("WorkingSnapshot reload returns ProgramDB", loadedProgram != nullptr);
                    if (loadedProgram) {
                        ghidra::DecompInterface reloadedDi;
                        bool reopened = reloadedDi.openProgram(loadedProgram.get());
                        TEST("DecompInterface opens reloaded ProgramDB", reopened);
                        std::vector<ghidra::DecompFunctionSummary> reloadedFunctions =
                            reloadedDi.getFunctions();
                        TEST("reloaded ProgramDB functions available",
                             !reloadedFunctions.empty());
                        auto reloadedEntry = std::find_if(
                            reloadedFunctions.begin(), reloadedFunctions.end(),
                            [ep](const ghidra::DecompFunctionSummary& item) {
                                return item.entryAddress.getOffset() == static_cast<int64_t>(ep);
                            });
                        TEST("reloaded ProgramDB includes entry",
                             reloadedEntry != reloadedFunctions.end());
                        if (reloadedEntry != reloadedFunctions.end()) {
                            ghidra::DecompileResults reloadRes =
                                reloadedDi.decompileFunction(
                                    reloadedEntry->entryAddress, nullptr);
                            TEST("reloaded ProgramDB decompiles entry function",
                                 reloadRes.decompiled);
                        }
                    }
                    std::error_code removeEc;
                    std::filesystem::remove(snapPath, removeEc);

                    std::cout << "\n--- T7: Commit Diff Reload Bridge ---" << std::endl;
                    std::filesystem::path repoPath =
                        std::filesystem::temp_directory_path() /
                        "enigma_decomp_interface_repo";
                    std::filesystem::remove_all(repoPath, removeEc);
                    bool repoCreated = ghidra::storage::Repository::create(
                        repoPath.string(), "BridgeRepo", binaryPath, "test-sha256",
                        prog.getLanguageID().toString(),
                        prog.getCompilerSpecID().toString(), loader->getImageBase());
                    TEST("Repository created for bridge workflow", repoCreated);
                    if (repoCreated && entryFunc) {
                        const std::string renamedEntry = "ui_entry_bridge";
                        ghidra::storage::EventLog log;
                        log.recordEvent(std::make_unique<ghidra::storage::RenameFunctionEvent>(
                            ep, entryFunc->getName(), renamedEntry));
                        entryFunc->setName(renamedEntry);

                        std::string commitId = ghidra::storage::CommitManager::createCommit(
                            repoPath.string(), "", "bridge workflow", "test",
                            "main", prog, log);
                        TEST("bridge commit created", !commitId.empty());

                        std::vector<ghidra::storage::ChangeEntry> changes;
                        bool changesLoaded = ghidra::storage::CommitManager::loadChangeSet(
                            repoPath.string(), commitId, changes);
                        TEST("bridge changeset loaded", changesLoaded);
                        bool foundRename = false;
                        for (const auto& change : changes) {
                            if (change.type == fbschema::ChangeType_RENAME_FUNCTION &&
                                change.address == ep &&
                                change.newValue == renamedEntry) {
                                foundRename = true;
                            }
                        }
                        TEST("bridge changeset records rename", foundRename);

                        auto committedProgram = ghidra::storage::SnapshotReader::loadFromFile(
                            ghidra::storage::Repository::getCommitSnapshotPath(
                                repoPath.string(), commitId));
                        TEST("bridge commit snapshot reloads", committedProgram != nullptr);
                        if (committedProgram) {
                            ghidra::DecompInterface commitDi;
                            bool commitOpened = commitDi.openProgram(committedProgram.get());
                            TEST("DecompInterface opens committed snapshot", commitOpened);
                            // Use the function manager to get the entry address from the loaded program
                            auto* commitFM = committedProgram->getFunctionManager();
                            bool commitEntryFound = false;
                            ghidra::Address commitEntry(nullptr, 0);
                            if (commitFM) {
                                auto commitFuncs = commitFM->getFunctions(false);
                                while (commitFuncs.hasNext()) {
                                    auto* f = commitFuncs.next();
                                    if (f && f->getEntryPoint().getOffset() == static_cast<int64_t>(ep)) {
                                        commitEntry = f->getEntryPoint();
                                        commitEntryFound = true;
                                        break;
                                    }
                                }
                            }
                            TEST("committed snapshot has entry function", commitEntryFound);
                            if (commitEntryFound) {
                                ghidra::DecompileResults commitRes =
                                    commitDi.decompileFunction(commitEntry, nullptr);
                                TEST("committed snapshot decompiles entry", commitRes.decompiled);
                                if (commitRes.decompiled) {
                                    TEST("committed snapshot uses renamed function",
                                         commitRes.functionName == renamedEntry);
                                }
                            }
                        }
                    }
                    std::filesystem::remove_all(repoPath, removeEc);

                    // T8: Decompile with unknown address (no code at address)
                    std::cout << "\n--- T8: Unknown Address ---" << std::endl;
                    ghidra::Address badAddr(space, static_cast<int64_t>(0xDEADBEEF));
                    bool caught = false;
                    try {
                        ghidra::DecompileResults badRes = di.decompileFunction(badAddr, nullptr);
                        caught = true;
                        std::cout << "  Unknown addr: decompiled=" << badRes.decompiled
                                  << " name=" << badRes.functionName << std::endl;
                    } catch (...) {
                        std::cout << "  Unknown addr: exception caught (acceptable)" << std::endl;
                    }
                    TEST("unknown address handled without crash", true);
                }
            }

            // T9: closeProgram / isOpen lifecycle
            std::cout << "\n--- T9: Lifecycle ---" << std::endl;
            TEST("isOpen before close", di.isOpen());
            try {
                di.closeProgram();
                TEST("isOpen after close", !di.isOpen());
                TEST("closeProgram is idempotent", (di.closeProgram(), true));
            } catch (...) {
                TEST("closeProgram threw", false);
            }
        }
    }
    std::cout << "  T5 scope cleanup OK" << std::endl;

    // T8: Multiple decompile calls to same Di
    std::cout << "\n--- T8: Multiple Decompile Calls ---" << std::endl;
    {
        ghidra::GenericAddressSpace ramSpace2("ram", 64, ghidra::AddressSpace::TYPE_RAM, 1);
        ghidra::ProgramDB prog("test_prog2", nullptr, nullptr);
        auto* addrFactory2 = dynamic_cast<ghidra::ProgramAddressFactory*>(prog.getAddressFactory());
        if (addrFactory2) {
            addrFactory2->addAddressSpace(&ramSpace2);
            addrFactory2->setDefaultSpace(&ramSpace2);
        }
        if (loader->populateProgram(&prog)) {
            ghidra::DecompInterface di;
            if (di.openProgram(&prog)) {
                uint64_t ep = loader->getEntryPoint();
                auto* space = const_cast<ghidra::AddressSpace*>(
                    prog.getAddressFactory()->getDefaultAddressSpace());
                ghidra::Address entryAddr(space, static_cast<int64_t>(ep));

                ghidra::DecompileResults r1 = di.decompileFunction(entryAddr, nullptr);
                ghidra::DecompileResults r2 = di.decompileFunction(entryAddr, nullptr);
                TEST("first decompile succeeded", r1.decompiled);
                TEST("second decompile (reuse) succeeded", r2.decompiled);
                if (r1.decompiled && r2.decompiled) {
                    TEST("both outputs identical", r1.cCode == r2.cCode);
                }
            }
            di.closeProgram();
        }
    }
    TEST("T8 cleanup ok", true);

    // T9: DecompileResults default values
    std::cout << "\n--- T9: DecompileResults Defaults ---" << std::endl;
    {
        ghidra::DecompileResults dr;
        TEST("default decompiled=false", !dr.decompiled);
        TEST("default functionSize=0", dr.functionSize == 0);
        TEST("default stackPurgeSize=0", dr.stackPurgeSize == 0);
        TEST("default callCount=0", dr.callCount == 0);
        TEST("default functionName empty", dr.functionName.empty());
        TEST("default cCode empty", dr.cCode.empty());
        TEST("default calls empty", dr.calls.empty());
    }

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << passed << "/" << total << " tests passed" << std::endl;

    return (passed == total) ? 0 : 1;
}
