#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/EventLog.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/CommentType.h>
#include <ghidra/AddressSet.h>

#include <fstream>
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
    ss << "repo_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    Repository::create(path, "test", "test.bin", "0000", "x86:LE:64:default", "gcc", 0x100000);
    return path;
}

int main() {
    // ------------------------------------------------------------------
    // CommitManager Basics
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        // Test creating a commit with no events
        std::string cid = CommitManager::createCommit(
            repoPath, "", "Initial commit", "testuser", "main", program, eventLog);
        TEST("createCommit returns non-empty ID", !cid.empty());

        // Test commit exists
        TEST("commitExists true", CommitManager::commitExists(repoPath, cid));
        TEST("commitExists false for bad ID", !CommitManager::commitExists(repoPath, "nonexistent"));

        // Test list commits - should have one
        auto commits = CommitManager::listCommits(repoPath);
        TEST("listCommits size 1", commits.size() == 1);
        if (commits.size() == 1) {
            TEST("listCommits first match", commits[0] == cid);
        }

        // Test load commit meta
        CommitInfo info;
        bool loaded = CommitManager::loadCommitMeta(repoPath, cid, info);
        TEST("loadCommitMeta succeeds", loaded);
        TEST("commitId matches", info.commitId == cid);
        TEST("message matches", info.message == "Initial commit");
        TEST("author matches", info.author == "testuser");
        TEST("branchName matches", info.branchName == "main");
        TEST("snapshotSize > 0", info.snapshotSize > 0);
        TEST("timestamp > 0", info.timestamp > 0);
        TEST("parentCommitId empty", info.parentCommitId == "");
        TEST("changeCount 0", info.changeCount == 0);

        // Test load non-existent commit
        CommitInfo badInfo;
        TEST("loadCommitMeta fails for bad ID",
             !CommitManager::loadCommitMeta(repoPath, "bad", badInfo));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Commit With Parent
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        std::string cid1 = CommitManager::createCommit(
            repoPath, "", "First", "user", "main", program, eventLog);
        std::string cid2 = CommitManager::createCommit(
            repoPath, cid1, "Second", "user", "main", program, eventLog);

        TEST("two commits created", !cid1.empty() && !cid2.empty());
        TEST("different IDs", cid1 != cid2);

        auto commits = CommitManager::listCommits(repoPath);
        TEST("listCommits size 2", commits.size() == 2);

        CommitInfo info;
        CommitManager::loadCommitMeta(repoPath, cid2, info);
        TEST("parent matches", info.parentCommitId == cid1);
        TEST("message matches", info.message == "Second");

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Generate ChangeSet from Events
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;

        EventLog eventLog;

        // Record rename function event
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "func1", "renamedFunc"));
        eventLog.recordEvent(std::make_unique<RenameSymbolEvent>(
            0x2000, "old_sym", "new_sym"));
        eventLog.recordEvent(std::make_unique<AddCommentEvent>(
            0x3000, CommentType::EOL, "hello"));

        std::string cid = CommitManager::createCommit(
            repoPath, "", "With changes", "user", "main", program, eventLog);

        CommitInfo info;
        CommitManager::loadCommitMeta(repoPath, cid, info);
        TEST("changeCount is 3", info.changeCount == 3);

        // Load changeset and verify
        std::vector<ChangeEntry> changes;
        bool loaded = CommitManager::loadChangeSet(repoPath, cid, changes);
        TEST("loadChangeSet succeeds", loaded);
        TEST("changes size 3", changes.size() == 3);

        if (changes.size() >= 3) {
            // Check rename function entry
            bool foundRenameFunc = false;
            bool foundRenameSym = false;
            bool foundAddComment = false;
            for (const auto& ch : changes) {
                if (ch.type == fb::ChangeType_RENAME_FUNCTION &&
                    ch.address == 0x1000) {
                    foundRenameFunc = true;
                    TEST("rename func oldValue", ch.oldValue == "func1");
                    TEST("rename func newValue", ch.newValue == "renamedFunc");
                }
                if (ch.type == fb::ChangeType_RENAME_SYMBOL &&
                    ch.address == 0x2000) {
                    foundRenameSym = true;
                    TEST("rename sym oldValue", ch.oldValue == "old_sym");
                    TEST("rename sym newValue", ch.newValue == "new_sym");
                }
                if (ch.type == fb::ChangeType_ADD_COMMENT &&
                    ch.address == 0x3000) {
                    foundAddComment = true;
                    TEST("comment name is EOL", ch.name == "EOL");
                    TEST("comment oldValue empty", ch.oldValue == "");
                    TEST("comment newValue", ch.newValue == "hello");
                }
            }
            TEST("found rename function entry", foundRenameFunc);
            TEST("found rename symbol entry", foundRenameSym);
            TEST("found add comment entry", foundAddComment);
        }

        // Test load non-existent changeset
        std::vector<ChangeEntry> badChanges;
        TEST("loadChangeSet fails for bad ID",
             !CommitManager::loadChangeSet(repoPath, "bad", badChanges));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // ChangeSet Compaction
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;

        EventLog eventLog;

        // Compaction should reduce this chain:
        // funcA → funcB → funcC → funcD
        // to: funcA → funcD
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "funcA", "funcB"));
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "funcB", "funcC"));
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "funcC", "funcD"));

        // Separate rename for 0x2000 (no compaction needed)
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x2000, "sub_2000", "networking_init"));

        // Separate rename for 0x3000 that gets renamed back (should cancel out)
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x3000, "start_3000", "temp_name"));
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x3000, "temp_name", "start_3000"));

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Compaction test", "user", "main", program, eventLog);

        std::vector<ChangeEntry> changes;
        CommitManager::loadChangeSet(repoPath, cid, changes);

        // Should have 2 entries: funcA→funcD and sub_2000→networking_init
        // start_3000→temp_name→start_3000 cancels out (old==new)
        TEST("compacted changes size 2", changes.size() == 2);

        if (changes.size() >= 2) {
            for (const auto& ch : changes) {
                if (ch.address == 0x1000) {
                    TEST("compacted old=funcA", ch.oldValue == "funcA");
                    TEST("compacted new=funcD", ch.newValue == "funcD");
                }
                if (ch.address == 0x2000) {
                    TEST("not-compacted old=sub_2000", ch.oldValue == "sub_2000");
                    TEST("not-compacted new=networking_init", ch.newValue == "networking_init");
                }
                TEST("0x3000 not in changeset", ch.address != 0x3000);
            }
        }

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Bookmark and DataType Events in ChangeSet
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        eventLog.recordEvent(std::make_unique<AddBookmarkEvent>(
            0x5000, "Note", "important analysis"));
        eventLog.recordEvent(std::make_unique<DeleteBookmarkEvent>(
            0x6000, "Info", "some info"));

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Bookmark test", "user", "main", program, eventLog);

        std::vector<ChangeEntry> changes;
        CommitManager::loadChangeSet(repoPath, cid, changes);
        TEST("bookmark changes size 2", changes.size() == 2);

        if (changes.size() >= 2) {
            for (const auto& ch : changes) {
                if (ch.type == fb::ChangeType_ADD_BOOKMARK) {
                    TEST("bookmark addr 0x5000", ch.address == 0x5000);
                    TEST("bookmark name Note", ch.name == "Note");
                    TEST("bookmark old empty", ch.oldValue == "");
                    TEST("bookmark new text", ch.newValue == "important analysis");
                }
                if (ch.type == fb::ChangeType_DELETE_BOOKMARK) {
                    TEST("bookmark addr 0x6000", ch.address == 0x6000);
                    TEST("bookmark name Info", ch.name == "Info");
                    TEST("bookmark old text", ch.oldValue == "some info");
                    TEST("bookmark new empty", ch.newValue == "");
                }
            }
        }

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Snapshot File Verification
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;

        EventLog eventLog;
        std::string cid = CommitManager::createCommit(
            repoPath, "", "Verify snapshot", "user", "main", program, eventLog);

        // Verify snapshot file exists and has content
        std::string snapPath = Repository::getCommitSnapshotPath(repoPath, cid);
        TEST("snapshot file exists", fs::exists(snapPath));
        size_t snapSize = fs::file_size(snapPath);
        TEST("snapshot file non-empty", snapSize > 0);

        // Verify changeset file exists
        std::string csPath = Repository::getCommitChangeSetPath(repoPath, cid);
        TEST("changeset file exists", fs::exists(csPath));
        TEST("changeset file non-empty", fs::file_size(csPath) > 0);

        // Verify commit meta file exists
        std::string metaPath = Repository::getCommitMetaPath(repoPath, cid);
        TEST("meta file exists", fs::exists(metaPath));
        TEST("meta file non-empty", fs::file_size(metaPath) > 0);

        // Commit dir exists
        TEST("commit dir exists", fs::exists(Repository::getCommitDir(repoPath, cid)));

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Multiple Commits with EventLog reuse
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        // First commit: empty
        std::string cid1 = CommitManager::createCommit(
            repoPath, "", "First", "user", "main", program, eventLog);

        // Add some events
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "old1", "new1"));

        // Second commit: with the rename event
        std::string cid2 = CommitManager::createCommit(
            repoPath, cid1, "Second", "user", "main", program, eventLog);

        TEST("cid2 changeCount 1", [&]() {
            CommitInfo info2;
            CommitManager::loadCommitMeta(repoPath, cid2, info2);
            return info2.changeCount == 1;
        }());

        // Add more events
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x2000, "old2", "new2"));
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x3000, "old3", "new3"));

        // Third commit: with rename 0x2000 and 0x3000
        std::string cid3 = CommitManager::createCommit(
            repoPath, cid2, "Third", "user", "main", program, eventLog);

        TEST("cid3 changeCount 3", [&]() {
            CommitInfo info3;
            CommitManager::loadCommitMeta(repoPath, cid3, info3);
            return info3.changeCount == 3;
        }());

        // First commit should still have changeCount 0
        TEST("cid1 changeCount 0", [&]() {
            CommitInfo info1;
            CommitManager::loadCommitMeta(repoPath, cid1, info1);
            return info1.changeCount == 0;
        }());

        // List should return 3 commits in order
        auto commits = CommitManager::listCommits(repoPath);
        TEST("3 commits total", commits.size() == 3);

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // CreateDataType and DeleteDataType in ChangeSet
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        CategoryPath cat("/");
        eventLog.recordEvent(std::make_unique<CreateDataTypeEvent>(
            "MyStruct", cat, 16, 0));
        eventLog.recordEvent(std::make_unique<DeleteDataTypeEvent>(
            "OldStruct", cat, 8, 1));

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Data type test", "user", "main", program, eventLog);

        std::vector<ChangeEntry> changes;
        CommitManager::loadChangeSet(repoPath, cid, changes);
        TEST("data type changes size 2", changes.size() == 2);

        for (const auto& ch : changes) {
            if (ch.type == fb::ChangeType_CREATE_DATA_TYPE) {
                TEST("create dt name", ch.name == "MyStruct");
                TEST("create dt old=empty", ch.oldValue == "");
                TEST("create dt new=16:0", ch.newValue == "16:0");
            }
            if (ch.type == fb::ChangeType_DELETE_DATA_TYPE) {
                TEST("delete dt name", ch.name == "OldStruct");
                TEST("delete dt old=8:1", ch.oldValue == "8:1");
                TEST("delete dt new=empty", ch.newValue == "");
            }
        }

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Empty EventLog (no events recorded)
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;
        EventLog eventLog;

        // Don't record any events — just create commit
        std::string cid = CommitManager::createCommit(
            repoPath, "", "No events", "user", "main", program, eventLog);

        std::vector<ChangeEntry> changes;
        CommitManager::loadChangeSet(repoPath, cid, changes);
        TEST("no events -> empty changes", changes.empty());

        CommitInfo info;
        CommitManager::loadCommitMeta(repoPath, cid, info);
        TEST("changeCount 0 for no events", info.changeCount == 0);

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // loadChangeSet on commit with no ChangeSet changes (edge case)
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        ProgramDB program;

        EventLog eventLog;
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "func", "renamed"));
        eventLog.recordEvent(std::make_unique<RenameFunctionEvent>(
            0x1000, "renamed", "func"));

        std::string cid = CommitManager::createCommit(
            repoPath, "", "Self cancel", "user", "main", program, eventLog);

        std::vector<ChangeEntry> changes;
        bool loaded = CommitManager::loadChangeSet(repoPath, cid, changes);
        TEST("load change set ok", loaded);
        TEST("self-canceling changes empty", changes.empty());

        CommitInfo info;
        CommitManager::loadCommitMeta(repoPath, cid, info);
        TEST("changeCount 0 for self-cancel", info.changeCount == 0);

        fs::remove_all(repoPath);
    }

    // ------------------------------------------------------------------
    // Repository with no commits
    // ------------------------------------------------------------------
    {
        std::string repoPath = createTempRepo();
        auto commits = CommitManager::listCommits(repoPath);
        TEST("empty repo -> 0 commits", commits.empty());

        TEST("commit exists false", !CommitManager::commitExists(repoPath, "any"));

        CommitInfo info;
        TEST("load meta fails", !CommitManager::loadCommitMeta(repoPath, "any", info));

        std::vector<ChangeEntry> changes;
        TEST("load changeset fails", !CommitManager::loadChangeSet(repoPath, "any", changes));

        fs::remove_all(repoPath);
    }

    std::cout << "\n=== Phase 3 Storage Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}
