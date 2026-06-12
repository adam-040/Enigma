#pragma once
#include "project_generated.h"
#include <string>
#include <vector>

namespace ghidra {
namespace storage {

struct BranchInfo {
    std::string name;
    std::string headCommitId;
};

class BranchManager {
public:
    /// Create a new branch pointing at the given commit.
    /// Returns true on success.
    static bool createBranch(const std::string& repoPath,
                              const std::string& branchName,
                              const std::string& commitId);

    /// List all branches in the repository.
    static std::vector<BranchInfo> listBranches(const std::string& repoPath);

    /// Delete a branch (cannot delete the current branch).
    /// Returns true on success.
    static bool deleteBranch(const std::string& repoPath,
                              const std::string& branchName);

    /// Switch the current branch to an existing branch.
    /// Returns true on success.
    static bool switchBranch(const std::string& repoPath,
                              const std::string& branchName);

    /// Get the name of the current branch.
    /// Returns empty string if repository is invalid.
    static std::string getCurrentBranch(const std::string& repoPath);

    /// Get the commit ID a branch points to.
    /// Returns empty string if the branch doesn't exist.
    static std::string getBranchCommit(const std::string& repoPath,
                                        const std::string& branchName);

    /// Check if a branch exists.
    static bool branchExists(const std::string& repoPath,
                              const std::string& branchName);

    /// Advance a branch head to a new commit.
    static bool advanceBranch(const std::string& repoPath,
                               const std::string& branchName,
                               const std::string& commitId);

private:
    /// Helper: read and verify project metadata, return parsed root.
    /// Caller must keep buf alive while using root.
    static const fbschema::ProjectMetadata* readMeta(
        const std::string& repoPath, std::vector<uint8_t>& buf);

    /// Helper: write project metadata.
    static bool writeMeta(const std::string& repoPath,
                           flatbuffers::FlatBufferBuilder& builder);
};

} // namespace storage
} // namespace ghidra
