#include <ghidra/storage/BranchManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/EventLog.h>
#include <ghidra/storage/Event.h>
#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/AddressSet.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/FunctionSignatureImpl.h>
#include <ghidra/ParameterDefinitionImpl.h>

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
    ss << "repo_reload_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    Repository::create(path, "test", "test.bin", "0000", "x86:LE:64:default", "gcc", 0x100000);
    return path;
}

int main() {
    // ================================================================
    // TEST: Full repository reload cycle
    //   ProgramDB → Save(Snapshot) → Commit → Branch → Close → Reopen 
    //   → Checkout Commit → Checkout Branch → Reload Snapshot
    // ================================================================
    {
        std::string repoPath = createTempRepo();

        ProgramDB progA;
        progA.initialize("mybinary", nullptr, nullptr);

        // Setup DTM with custom types
        auto* dtmOrig = progA.getDataTypeManager();
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtmOrig);
        auto* dwordDt = new DWordDataType(dtmImpl);
        dtmImpl->addDataType(dwordDt);
        dtmImpl->addDataType(new BooleanDataType(dtmImpl));

        Address entry(nullptr, 0x1000);
        AddressSet body(entry, Address(nullptr, 0x10FF));

        // Create function with signatures
        auto* fm = progA.getFunctionManager();
        auto* func = fm->createFunction("MyFunc", entry, body, SourceType::USER_DEFINED);
        TEST("rt.func_created", func != nullptr);

        auto* sig = new FunctionSignatureImpl("MyFunc");
        sig->setReturnType(dtmOrig->getDataType(CategoryPath::ROOT(), "void"));
        sig->setCallingConventionName("__stdcall");

        func->setSignature(sig, SignatureSource::KNOWN_LIBRARY);
        func->setReturnType(sig->getReturnType(), SignatureSource::KNOWN_LIBRARY);
        func->setHasNoReturn(false, SignatureSource::KNOWN_LIBRARY);

        // Create a symbol
        auto* st = progA.getSymbolTable();
        st->createLabel(entry, "myfunc_label", SourceType::USER_DEFINED);

        // ---- Phase 1: Save and Commit ----
        EventLog log1;
        std::string cid1 = CommitManager::createCommit(
            repoPath, "", "Initial commit with signatures", "user", "main", progA, log1);
        TEST("rt.commit1", !cid1.empty());

        // ---- Phase 2: Create Branches ----
        BranchManager::createBranch(repoPath, "dev", cid1);
        BranchManager::createBranch(repoPath, "research", cid1);

        auto branches = BranchManager::listBranches(repoPath);
        TEST("rt.branches_count", branches.size() >= 3);
        bool foundMain = false, foundDev = false, foundResearch = false;
        for (auto& b : branches) {
            if (b.name == "main")     foundMain = true;
            if (b.name == "dev")      foundDev = true;
            if (b.name == "research") foundResearch = true;
        }
        TEST("rt.branch_main", foundMain);
        TEST("rt.branch_dev", foundDev);
        TEST("rt.branch_research", foundResearch);

        // ---- Phase 3: Switch to dev branch and make changes ----
        BranchManager::switchBranch(repoPath, "dev");
        ProgramDB progDev;
        progDev.initialize("mybinary", nullptr, nullptr);

        Address entryDev(nullptr, 0x1000);
        AddressSet bodyDev(entryDev, Address(nullptr, 0x10FF));
        auto* fmDev = progDev.getFunctionManager();
        auto* funcDev = fmDev->createFunction("MyFunc_dev", entryDev, bodyDev, SourceType::USER_DEFINED);

        EventLog log2;
        std::string cid2 = CommitManager::createCommit(
            repoPath, cid1, "Dev branch commit", "user", "dev", progDev, log2);
        TEST("rt.commit2", !cid2.empty());

        // ---- Phase 4: Switch to research branch and make different changes ----
        BranchManager::switchBranch(repoPath, "research");
        ProgramDB progResearch;
        progResearch.initialize("mybinary", nullptr, nullptr);

        auto* fmRes = progResearch.getFunctionManager();
        auto* funcRes = fmRes->createFunction("MyFunc_research", entry, body, SourceType::USER_DEFINED);
        auto* sigRes = new FunctionSignatureImpl("MyFunc_research");
        sigRes->setReturnType(progResearch.getDataTypeManager()->getDataType(CategoryPath::ROOT(), "void"));
        funcRes->setSignature(sigRes, SignatureSource::KNOWN_LIBRARY);

        EventLog log3;
        std::string cid3 = CommitManager::createCommit(
            repoPath, cid1, "Research branch commit", "user", "research", progResearch, log3);
        TEST("rt.commit3", !cid3.empty());

        // ---- Phase 5: Verify independent branch histories ----
        auto commitsDev = CommitManager::listCommits(repoPath);
        TEST("rt.some_commits", !commitsDev.empty());

        // Verify branch pointers auto-advance after commit
        std::string devHead = BranchManager::getBranchCommit(repoPath, "dev");
        std::string resHead = BranchManager::getBranchCommit(repoPath, "research");
        TEST("rt.dev_head_auto", devHead == cid2);
        TEST("rt.res_head_auto", resHead == cid3);
        TEST("rt.branches_independent", devHead != resHead);

        // ---- Phase 6: Switch back to main ----
        BranchManager::switchBranch(repoPath, "main");
        TEST("rt.back_to_main", BranchManager::getCurrentBranch(repoPath) == "main");

        // ---- Phase 7: "Close" and "Reopen" (simulated) ----
        // Store repo path, then verify all state survives
        // The metadata is all on disk (FlatBuffers), so reopening is just
        // calling the same stateless static methods

        // Verify main still works
        TEST("rt.reopened_main", BranchManager::getCurrentBranch(repoPath) == "main");
        auto reopenedBranches = BranchManager::listBranches(repoPath);
        TEST("rt.reopened_branches", reopenedBranches.size() >= 3);

        // Verify commit metadata survives
        CommitInfo info;
        TEST("rt.reopened_meta", CommitManager::loadCommitMeta(repoPath, cid1, info));
        TEST("rt.reopened_msg", info.message == "Initial commit with signatures");

        // ---- Phase 8: Load snapshot from commit and verify ----
        std::string snapPath = Repository::getCommitSnapshotPath(repoPath, cid1);
        auto restored = SnapshotReader::loadFromFile(snapPath);
        TEST("rt.snapshot_loaded", restored != nullptr);

        auto* restFm = restored->getFunctionManager();
        auto* restFunc = restFm ? restFm->getFunctionAt(entry) : nullptr;
        TEST("rt.restored_func_exists", restFunc != nullptr);

        if (restFunc) {
            TEST("rt.restored_name", restFunc->getName() == "MyFunc");
            TEST("rt.restored_ret", restFunc->getReturnType() &&
                 restFunc->getReturnType()->getName() == "void");
            TEST("rt.restored_noreturn", !restFunc->hasNoReturn());
            TEST("rt.restored_source",
                 restFunc->getSignatureSource() == SignatureSource::KNOWN_LIBRARY);
        }

        // verify symbols
        auto* restSt = restored->getSymbolTable();
        TEST("rt.symbol_exists", restSt && restSt->getPrimarySymbol(entry) != nullptr);

        // verify functions count
        int funcCount = 0;
        if (restFm) {
            auto it = restFm->getFunctions(true);
            while (it.hasNext()) { it.next(); funcCount++; }
        }
        TEST("rt.func_count", funcCount >= 1);

        // ---- Phase 9: Commit → Branch → Delete → Verify ----
        BranchManager::switchBranch(repoPath, "main");
        TEST("rt.delete.research", BranchManager::deleteBranch(repoPath, "research"));
        TEST("rt.delete.research_gone", !BranchManager::branchExists(repoPath, "research"));
        auto afterDelete = BranchManager::listBranches(repoPath);
        TEST("rt.after_delete_count", afterDelete.size() >= 2);

        fs::remove_all(repoPath);
    }

    // ================================================================
    // TEST: Data type round-trip
    // ================================================================
    {
        std::string repoPath = createTempRepo();

        ProgramDB prog;
        prog.initialize("typed_bin", nullptr, nullptr);

        auto* dtm = prog.getDataTypeManager();
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtm);

        // Register custom types
        dtmImpl->addDataType(new DWordDataType(dtmImpl));
        dtmImpl->addDataType(new BooleanDataType(dtmImpl));

        Address entry(nullptr, 0x2000);
        AddressSet body(entry, Address(nullptr, 0x20FF));
        auto* fm = prog.getFunctionManager();
        auto* func = fm->createFunction("TypedFunc", entry, body, SourceType::USER_DEFINED);

        auto* dwordDt = dtm->getDataType(CategoryPath::ROOT(), "dword");
        func->setReturnType(dwordDt, SignatureSource::KNOWN_LIBRARY);

        EventLog log;
        std::string cid = CommitManager::createCommit(
            repoPath, "", "Typed commit", "user", "main", prog, log);

        // Load snapshot
        std::string snapPath = Repository::getCommitSnapshotPath(repoPath, cid);
        auto restored = SnapshotReader::loadFromFile(snapPath);
        TEST("dt.snapshot_loaded", restored != nullptr);

        // Verify DTM has custom types in restored program
        auto* restDtm = restored->getDataTypeManager();
        auto* restDword = restDtm ? restDtm->getDataType(CategoryPath::ROOT(), "dword") : nullptr;
        TEST("dt.restored_dword", restDword != nullptr);

        auto* restFunc = restored->getFunctionManager()->getFunctionAt(entry);
        TEST("dt.restored_func", restFunc != nullptr);
        if (restFunc && restDword) {
            TEST("dt.restored_ret_dword",
                 restFunc->getReturnType() && restFunc->getReturnType() == restDword);
        }

        fs::remove_all(repoPath);
    }

    // ================================================================
    // TEST: Undo/Redo with restored program
    // ================================================================
    {
        std::string repoPath = createTempRepo();

        ProgramDB prog;
        prog.initialize("build_process", nullptr, nullptr);

        Address entry(nullptr, 0x3000);
        AddressSet body(entry, Address(nullptr, 0x30FF));
        auto* fm = prog.getFunctionManager();
        auto* func = fm->createFunction("BuildFunc", entry, body, SourceType::USER_DEFINED);

        func->setHasNoReturn(true, SignatureSource::KNOWN_LIBRARY);
        TEST("nr.initial_true", func->hasNoReturn());

        EventLog log;
        log.recordEvent(std::make_unique<SetNoReturnEvent>(
            entry.getOffset(), "BuildFunc", false, true));

        // Undo via EventLog
        log.undo(prog);
        TEST("nr.undo_false", !func->hasNoReturn());

        // Redo via EventLog
        log.redo(prog);
        TEST("nr.redo_true", func->hasNoReturn());

        // Save and reload snapshot, verify noreturn survives
        EventLog commitLog;
        std::string cid = CommitManager::createCommit(
            repoPath, "", "The Build Process commit", "user", "main", prog, commitLog);

        std::string snapPath = Repository::getCommitSnapshotPath(repoPath, cid);
        auto restored = SnapshotReader::loadFromFile(snapPath);
        auto* restFunc = restored->getFunctionManager()->getFunctionAt(entry);
        TEST("nr.restored_func", restFunc != nullptr);
        TEST("nr.restored_noreturn", restFunc && restFunc->hasNoReturn());

        fs::remove_all(repoPath);
    }

    std::cout << "\n=== Repository Reload Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}
