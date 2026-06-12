#include <ghidra/storage/BranchManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/EventLog.h>
#include <ghidra/ProgramDB.h>

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
    ss << "repo_branch_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    Repository::create(path, "test", "test.bin", "0000", "x86:LE:64:default", "gcc", 0x100000);
    return path;
}

int main() {
    // ------------------------------------------------------------------
    // Default branch after repo creation
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        TEST("current branch is main", BranchManager::getCurrentBranch(repoPath) == "main");
        TEST("branchExists main", BranchManager::branchExists(repoPath, "main"));

        auto branches = BranchManager::listBranches(repoPath);
        TEST("listBranches size 1", branches.size() == 1);
        if (branches.size() == 1) {
            TEST("branch name is main", branches[0].name == "main");
            TEST("branch commit empty", branches[0].headCommitId == "");
        }

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Create branch pointing at existing commit
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        // Create a commit first
        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial", "user", "main", program, eventLog);
        TEST("commit created", !cid.empty());

        // Create branch pointing at that commit
        bool created = BranchManager::createBranch(repoPath, "feature", cid);
        TEST("createBranch feature", created);

        TEST("branchExists feature", BranchManager::branchExists(repoPath, "feature"));
        TEST("branchExists main still", BranchManager::branchExists(repoPath, "main"));

        std::string branchCommit = BranchManager::getBranchCommit(repoPath, "feature");
        TEST("feature points to commit", branchCommit == cid);

        std::string mainCommit = BranchManager::getBranchCommit(repoPath, "main");
        TEST("main points to commit after auto-advance", mainCommit == cid);

        auto branches = BranchManager::listBranches(repoPath);
        TEST("listBranches size 2", branches.size() == 2);

        // Current branch should still be main
        TEST("current branch still main",
             BranchManager::getCurrentBranch(repoPath) == "main");

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Create branch with duplicate name fails
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial", "user", "main", program, eventLog);

        TEST("createBranch main fails",
             !BranchManager::createBranch(repoPath, "main", cid));
        TEST("createBranch empty name fails",
             !BranchManager::createBranch(repoPath, "", cid));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Create branch with non-existent commit fails
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        bool created = BranchManager::createBranch(repoPath, "fix", "nonexistent");
        TEST("createBranch with bad commit fails", !created);
        TEST("branch not created", !BranchManager::branchExists(repoPath, "fix"));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Switch branches
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial", "user", "main", program, eventLog);
        BranchManager::createBranch(repoPath, "dev", cid);

        TEST("current branch is main before switch",
             BranchManager::getCurrentBranch(repoPath) == "main");

        bool switched = BranchManager::switchBranch(repoPath, "dev");
        TEST("switch to dev succeeds", switched);

        TEST("current branch is dev after switch",
             BranchManager::getCurrentBranch(repoPath) == "dev");

        // Switch to non-existent branch fails
        TEST("switch to bad fails",
             !BranchManager::switchBranch(repoPath, "nonexistent"));

        // Switch back to main
        TEST("switch back to main", BranchManager::switchBranch(repoPath, "main"));
        TEST("current branch back to main",
             BranchManager::getCurrentBranch(repoPath) == "main");

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Delete branch
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial", "user", "main", program, eventLog);
        BranchManager::createBranch(repoPath, "experiment", cid);
        BranchManager::createBranch(repoPath, "research", cid);

        TEST("3 branches exist",
             BranchManager::listBranches(repoPath).size() == 3);

        // Delete a branch
        bool deleted = BranchManager::deleteBranch(repoPath, "experiment");
        TEST("deleteBranch experiment", deleted);

        TEST("experiment gone", !BranchManager::branchExists(repoPath, "experiment"));
        TEST("research still exists", BranchManager::branchExists(repoPath, "research"));
        TEST("main still exists", BranchManager::branchExists(repoPath, "main"));

        auto branches = BranchManager::listBranches(repoPath);
        TEST("listBranches size 2", branches.size() == 2);

        // Cannot delete current branch
        TEST("delete main fails", !BranchManager::deleteBranch(repoPath, "main"));

        // Cannot delete non-existent branch
        TEST("delete non-existent fails",
             !BranchManager::deleteBranch(repoPath, "phantom"));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Switch then delete
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial", "user", "main", program, eventLog);
        BranchManager::createBranch(repoPath, "side", cid);
        BranchManager::switchBranch(repoPath, "side");

        // main is no longer current, can delete it
        bool deleted = BranchManager::deleteBranch(repoPath, "main");
        TEST("delete main after switching", deleted);

        TEST("main gone", !BranchManager::branchExists(repoPath, "main"));
        TEST("side still exists", BranchManager::branchExists(repoPath, "side"));
        TEST("current branch is side", BranchManager::getCurrentBranch(repoPath) == "side");

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // BranchInfo from listBranches
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid1 = CommitManager::createCommit(
            repoPath, "", "First", "user", "main", program, eventLog);
        std::string cid2 = CommitManager::createCommit(
            repoPath, cid1, "Second", "user", "main", program, eventLog);

        BranchManager::createBranch(repoPath, "stable", cid1);
        BranchManager::createBranch(repoPath, "latest", cid2);

        auto branches = BranchManager::listBranches(repoPath);
        TEST("3 branches total", branches.size() == 3);

        bool foundMain = false, foundStable = false, foundLatest = false;
        for (const auto& b : branches) {
            if (b.name == "main")    { foundMain = true;    TEST("main commit auto-advance", !b.headCommitId.empty()); }
            if (b.name == "stable")  { foundStable = true;  TEST("stable commit 1",      b.headCommitId == cid1); }
            if (b.name == "latest")  { foundLatest = true;  TEST("latest commit 2",      b.headCommitId == cid2); }
        }
        TEST("found main branch", foundMain);
        TEST("found stable branch", foundStable);
        TEST("found latest branch", foundLatest);

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // getBranchCommit for non-existent branch
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        std::string commit = BranchManager::getBranchCommit(repoPath, "nope");
        TEST("getBranchCommit bad branch empty", commit == "");

        commit = BranchManager::getBranchCommit(repoPath, "main");
        TEST("getBranchCommit main empty (no commits)", commit == "");

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // branchExists basic
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();

        TEST("branchExists main", BranchManager::branchExists(repoPath, "main"));
        TEST("!branchExists other", !BranchManager::branchExists(repoPath, "other"));
        TEST("!branchExists empty name", !BranchManager::branchExists(repoPath, ""));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Delete all non-current branches
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial", "user", "main", program, eventLog);
        BranchManager::createBranch(repoPath, "a", cid);
        BranchManager::createBranch(repoPath, "b", cid);
        BranchManager::createBranch(repoPath, "c", cid);

        TEST("4 branches total", BranchManager::listBranches(repoPath).size() == 4);

        TEST("delete a", BranchManager::deleteBranch(repoPath, "a"));
        TEST("delete b", BranchManager::deleteBranch(repoPath, "b"));
        TEST("delete c", BranchManager::deleteBranch(repoPath, "c"));

        auto branches = BranchManager::listBranches(repoPath);
        TEST("only main left", branches.size() == 1);
        if (branches.size() == 1) {
            TEST("main is only branch", branches[0].name == "main");
        }

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Operations on invalid repo path
    // ------------------------------------------------------------------
    {
        std::string badPath = "nonexistent_repo_path";

        TEST("getCurrentBranch fails", BranchManager::getCurrentBranch(badPath) == "");
        TEST("listBranches empty", BranchManager::listBranches(badPath).empty());
        TEST("branchExists false",
             !BranchManager::branchExists(badPath, "main"));
        TEST("createBranch fails",
             !BranchManager::createBranch(badPath, "x", "y"));
        TEST("deleteBranch fails",
             !BranchManager::deleteBranch(badPath, "x"));
        TEST("switchBranch fails",
             !BranchManager::switchBranch(badPath, "x"));
        TEST("getBranchCommit fails",
             BranchManager::getBranchCommit(badPath, "x") == "");
    }

    std::cout << "\n=== Phase 4 Storage Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}
