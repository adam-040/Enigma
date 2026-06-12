/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Repository.h
/// \brief Manages the repository directory layout and metadata.
#pragma once

#include <string>
#include <cstdint>

namespace ghidra {
namespace storage {

class Repository {
public:
    /// Create a new repository at the given path.
    /// Returns true on success.
    static bool create(const std::string& path,
                       const std::string& projectName,
                       const std::string& binaryName,
                       const std::string& binarySha256,
                       const std::string& languageId,
                       const std::string& compilerSpecId,
                       uint64_t imageBase);

    /// Open an existing repository. Verifies directory structure.
    /// Returns true if the repository is valid.
    static bool open(const std::string& path);

    /// Path accessors
    static std::string getMetadataDir(const std::string& repoPath);
    static std::string getWorkingDir(const std::string& repoPath);
    static std::string getCommitsDir(const std::string& repoPath);
    static std::string getIndexDir(const std::string& repoPath);
    static std::string getBinaryDir(const std::string& repoPath);

    static std::string getProjectMetaPath(const std::string& repoPath);
    static std::string getBranchesMetaPath(const std::string& repoPath);
    static std::string getWorkingSnapshotPath(const std::string& repoPath);
    static std::string getCommitDir(const std::string& repoPath, const std::string& commitId);
    static std::string getCommitSnapshotPath(const std::string& repoPath, const std::string& commitId);
    static std::string getCommitChangeSetPath(const std::string& repoPath, const std::string& commitId);
    static std::string getCommitMetaPath(const std::string& repoPath, const std::string& commitId);
};

} // namespace storage
} // namespace ghidra
