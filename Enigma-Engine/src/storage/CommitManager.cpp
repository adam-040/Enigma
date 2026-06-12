#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/BranchManager.h>
#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/CommentType.h>
#include "changeset_generated.h"
#include "commit_generated.h"
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <map>
#include <sstream>
#include <chrono>
#include <ctime>
#include <algorithm>

namespace ghidra {
namespace storage {

namespace fb = fbschema;
namespace fs = std::filesystem;

static void eventToChange(const Event& ev, fb::ChangeType& type,
                           uint64_t& address, std::string& name,
                           std::string& oldValue, std::string& newValue) {
    type = ev.getType();
    address = ev.getAddress();
    name = ev.getChangeSetName();
    oldValue = ev.getOldValue();
    newValue = ev.getNewValue();
}

std::string CommitManager::generateCommitId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    std::stringstream ss;
    ss << std::hex << ms;
    return ss.str();
}

std::vector<uint8_t> CommitManager::generateChangeSet(const std::string& commitId,
                                                       const std::string& parentCommitId,
                                                       EventLog& eventLog) {
    struct CompactEntry {
        std::string oldValue;
        std::string newValue;
    };
    std::map<std::tuple<fb::ChangeType, uint64_t, std::string>, CompactEntry> compacted;

    for (const auto& evPtr : eventLog.getEvents()) {
        if (!evPtr) continue;
        fb::ChangeType type;
        uint64_t address;
        std::string name, oldValue, newValue;
        eventToChange(*evPtr, type, address, name, oldValue, newValue);

        auto key = std::make_tuple(type, address, name);
        auto it = compacted.find(key);
        if (it == compacted.end()) {
            compacted[key] = {oldValue, newValue};
        } else {
            it->second.newValue = newValue;
        }
    }

    flatbuffers::FlatBufferBuilder builder(1024);
    std::vector<flatbuffers::Offset<fb::Change>> changes;
    for (const auto& kv : compacted) {
        const auto& key = kv.first;
        const auto& entry = kv.second;
        if (entry.oldValue == entry.newValue) continue;
        auto nameStr = builder.CreateString(std::get<2>(key));
        auto oldStr = builder.CreateString(entry.oldValue);
        auto newStr = builder.CreateString(entry.newValue);
        changes.push_back(fb::CreateChange(builder, std::get<0>(key),
                                            std::get<1>(key),
                                            nameStr, oldStr, newStr));
    }

    auto commitIdStr = builder.CreateString(commitId);
    auto parentStr = builder.CreateString(parentCommitId);
    auto changesVec = builder.CreateVector(changes);
    auto cs = fb::CreateChangeSet(builder, 1, parentStr, commitIdStr, changesVec);
    builder.Finish(cs);

    return std::vector<uint8_t>(
        builder.GetBufferPointer(),
        builder.GetBufferPointer() + builder.GetSize());
}

std::string CommitManager::createCommit(const std::string& repoPath,
                                         const std::string& parentCommitId,
                                         const std::string& message,
                                         const std::string& author,
                                         const std::string& branchName,
                                         ProgramDB& program,
                                         EventLog& eventLog) {
    std::string commitId = generateCommitId();
    std::string commitDir = Repository::getCommitDir(repoPath, commitId);
    if (!fs::create_directories(commitDir)) return "";

    // Write snapshot
    auto snapshotData = SnapshotWriter::serialize(program);
    std::string snapshotPath = Repository::getCommitSnapshotPath(repoPath, commitId);
    if (!SnapshotWriter::writeFile(snapshotPath, snapshotData)) return "";

    // Write changeset
    auto changesetData = generateChangeSet(commitId, parentCommitId, eventLog);
    std::string changesetPath = Repository::getCommitChangeSetPath(repoPath, commitId);
    std::ofstream csOut(changesetPath, std::ios::binary);
    if (!csOut) return "";
    csOut.write(reinterpret_cast<const char*>(changesetData.data()),
                static_cast<std::streamsize>(changesetData.size()));
    if (!csOut.good()) return "";

    // Write commit metadata
    flatbuffers::FlatBufferBuilder builder(1024);
    auto commitIdStr = builder.CreateString(commitId);
    auto parentStr = builder.CreateString(parentCommitId);
    auto msgStr = builder.CreateString(message);
    auto branchStr = builder.CreateString(branchName);
    auto authorStr = builder.CreateString(author);
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // Count changes from changeset
    auto* csRoot = fb::GetChangeSet(changesetData.data());
    int changeCount = csRoot->changes() ? static_cast<int>(csRoot->changes()->size()) : 0;

    auto meta = fb::CreateCommitMetadata(builder, 1, commitIdStr, parentStr,
        0, 0,
        snapshotData.size(), now, msgStr, branchStr, authorStr, changeCount);
    builder.Finish(meta);

    std::string metaPath = Repository::getCommitMetaPath(repoPath, commitId);
    std::ofstream metaOut(metaPath, std::ios::binary);
    if (!metaOut) return "";
    metaOut.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
                  static_cast<std::streamsize>(builder.GetSize()));
    if (!metaOut.good()) return "";

    // Advance branch head if this branch exists
    if (!branchName.empty() && BranchManager::branchExists(repoPath, branchName)) {
        BranchManager::advanceBranch(repoPath, branchName, commitId);
    }

    return commitId;
}

bool CommitManager::loadCommitMeta(const std::string& repoPath,
                                    const std::string& commitId,
                                    CommitInfo& info) {
    std::string metaPath = Repository::getCommitMetaPath(repoPath, commitId);
    if (!fs::exists(metaPath)) return false;

    std::ifstream in(metaPath, std::ios::binary | std::ios::ate);
    if (!in) return false;
    size_t size = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    if (!in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size)))
        return false;

    flatbuffers::Verifier verifier(buf.data(), buf.size());
    if (!fb::VerifyCommitMetadataBuffer(verifier)) return false;

    auto* meta = fb::GetCommitMetadata(buf.data());
    info.commitId = meta->commit_id()->str();
    info.parentCommitId = meta->parent_commit_id()->str();
    if (meta->snapshot_sha256()) info.snapshotSha256 = meta->snapshot_sha256()->str();
    info.snapshotSize = meta->snapshot_size();
    info.timestamp = meta->timestamp();
    info.message = meta->message()->str();
    info.branchName = meta->branch_name()->str();
    info.author = meta->author()->str();
    info.changeCount = meta->change_count();
    return true;
}

std::vector<std::string> CommitManager::listCommits(const std::string& repoPath) {
    std::vector<std::string> result;
    std::string commitsDir = Repository::getCommitsDir(repoPath);
    if (!fs::exists(commitsDir)) return result;

    for (const auto& entry : fs::directory_iterator(commitsDir)) {
        if (entry.is_directory()) {
            std::string dirName = entry.path().filename().string();
            std::string metaPath = entry.path().string() + "/commit.meta";
            if (fs::exists(metaPath)) {
                result.push_back(dirName);
            }
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}

bool CommitManager::loadChangeSet(const std::string& repoPath,
                                   const std::string& commitId,
                                   std::vector<ChangeEntry>& changes) {
    std::string csPath = Repository::getCommitChangeSetPath(repoPath, commitId);
    if (!fs::exists(csPath)) return false;

    std::ifstream in(csPath, std::ios::binary | std::ios::ate);
    if (!in) return false;
    size_t size = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    if (!in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size)))
        return false;

    flatbuffers::Verifier verifier(buf.data(), buf.size());
    if (!fb::VerifyChangeSetBuffer(verifier)) return false;

    auto* cs = fb::GetChangeSet(buf.data());
    if (!cs->changes()) return true;

    changes.clear();
    for (auto* ch : *cs->changes()) {
        ChangeEntry entry;
        entry.type = ch->change_type();
        entry.address = ch->address();
        if (ch->name()) entry.name = ch->name()->str();
        if (ch->old_value()) entry.oldValue = ch->old_value()->str();
        if (ch->new_value()) entry.newValue = ch->new_value()->str();
        changes.push_back(entry);
    }
    return true;
}

bool CommitManager::commitExists(const std::string& repoPath, const std::string& commitId) {
    std::string metaPath = Repository::getCommitMetaPath(repoPath, commitId);
    return fs::exists(metaPath);
}

} // namespace storage
} // namespace ghidra
