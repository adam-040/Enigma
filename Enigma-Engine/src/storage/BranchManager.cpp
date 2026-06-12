#include <ghidra/storage/BranchManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/CommitManager.h>
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <algorithm>

namespace ghidra {
namespace storage {

namespace fb = fbschema;
namespace fs = std::filesystem;

static bool readMetaFile(const std::string& path, std::vector<uint8_t>& buf) {
    if (!fs::exists(path)) return false;
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    size_t size = static_cast<size_t>(in.tellg());
    in.seekg(0);
    buf.resize(size);
    if (!in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size)))
        return false;
    flatbuffers::Verifier verifier(buf.data(), buf.size());
    return fb::VerifyProjectMetadataBuffer(verifier);
}

bool BranchManager::createBranch(const std::string& repoPath,
                                  const std::string& branchName,
                                  const std::string& commitId) {
    if (branchName.empty()) return false;
    if (!Repository::open(repoPath)) return false;
    if (!CommitManager::commitExists(repoPath, commitId)) return false;

    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return false;

    auto* meta = fb::GetProjectMetadata(buf.data());

    // Check if branch already exists
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) return false;
        }
    }

    // Rebuild with new branch added
    flatbuffers::FlatBufferBuilder builder(1024);
    auto nameStr = builder.CreateString(meta->project_name()->str());
    auto binStr = builder.CreateString(meta->binary_name()->str());
    auto shaStr = meta->binary_sha256() ? builder.CreateString(meta->binary_sha256()->str()) : 0;
    auto langStr = meta->language_id() ? builder.CreateString(meta->language_id()->str()) : 0;
    auto compStr = meta->compiler_spec_id() ? builder.CreateString(meta->compiler_spec_id()->str()) : 0;
    auto curBranchStr = builder.CreateString(meta->current_branch()->str());
    uint64_t created = meta->created_timestamp();
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // Build branch list
    std::vector<flatbuffers::Offset<fb::BranchPointer>> branchOffsets;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            auto n = builder.CreateString(bp->name()->str());
            auto h = builder.CreateString(bp->head_commit_id()->str());
            branchOffsets.push_back(fb::CreateBranchPointer(builder, n, h));
        }
    }
    {
        auto n = builder.CreateString(branchName);
        auto h = builder.CreateString(commitId);
        branchOffsets.push_back(fb::CreateBranchPointer(builder, n, h));
    }
    auto branchesVec = builder.CreateVector(branchOffsets);

    auto newMeta = fb::CreateProjectMetadata(builder, 1, 1, nameStr, binStr, shaStr,
        created, now, curBranchStr, branchesVec, langStr, compStr,
        meta->image_base());
    builder.Finish(newMeta);

    std::ofstream out(metaPath, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
              static_cast<std::streamsize>(builder.GetSize()));
    return out.good();
}

std::vector<BranchInfo> BranchManager::listBranches(const std::string& repoPath) {
    std::vector<BranchInfo> result;
    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return result;

    auto* meta = fb::GetProjectMetadata(buf.data());
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            BranchInfo info;
            info.name = bp->name()->str();
            info.headCommitId = bp->head_commit_id()->str();
            result.push_back(info);
        }
    }
    return result;
}

bool BranchManager::deleteBranch(const std::string& repoPath,
                                  const std::string& branchName) {
    if (branchName.empty()) return false;
    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return false;

    auto* meta = fb::GetProjectMetadata(buf.data());

    // Cannot delete current branch
    if (meta->current_branch()->str() == branchName) return false;

    // Find and remove the branch
    bool found = false;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) {
                found = true;
                break;
            }
        }
    }
    if (!found) return false;

    flatbuffers::FlatBufferBuilder builder(1024);
    auto nameStr = builder.CreateString(meta->project_name()->str());
    auto binStr = builder.CreateString(meta->binary_name()->str());
    auto shaStr = meta->binary_sha256() ? builder.CreateString(meta->binary_sha256()->str()) : 0;
    auto langStr = meta->language_id() ? builder.CreateString(meta->language_id()->str()) : 0;
    auto compStr = meta->compiler_spec_id() ? builder.CreateString(meta->compiler_spec_id()->str()) : 0;
    auto curBranchStr = builder.CreateString(meta->current_branch()->str());
    uint64_t created = meta->created_timestamp();
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    std::vector<flatbuffers::Offset<fb::BranchPointer>> branchOffsets;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) continue;
            auto n = builder.CreateString(bp->name()->str());
            auto h = builder.CreateString(bp->head_commit_id()->str());
            branchOffsets.push_back(fb::CreateBranchPointer(builder, n, h));
        }
    }
    auto branchesVec = builder.CreateVector(branchOffsets);

    auto newMeta = fb::CreateProjectMetadata(builder, 1, 1, nameStr, binStr, shaStr,
        created, now, curBranchStr, branchesVec, langStr, compStr,
        meta->image_base());
    builder.Finish(newMeta);

    std::ofstream out(metaPath, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
              static_cast<std::streamsize>(builder.GetSize()));
    return out.good();
}

bool BranchManager::switchBranch(const std::string& repoPath,
                                  const std::string& branchName) {
    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return false;

    auto* meta = fb::GetProjectMetadata(buf.data());

    // Verify branch exists
    bool found = false;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) {
                found = true;
                break;
            }
        }
    }
    if (!found) return false;

    // Already on this branch
    if (meta->current_branch()->str() == branchName) return true;

    flatbuffers::FlatBufferBuilder builder(1024);
    auto nameStr = builder.CreateString(meta->project_name()->str());
    auto binStr = builder.CreateString(meta->binary_name()->str());
    auto shaStr = meta->binary_sha256() ? builder.CreateString(meta->binary_sha256()->str()) : 0;
    auto langStr = meta->language_id() ? builder.CreateString(meta->language_id()->str()) : 0;
    auto compStr = meta->compiler_spec_id() ? builder.CreateString(meta->compiler_spec_id()->str()) : 0;
    auto curBranchStr = builder.CreateString(branchName);
    uint64_t created = meta->created_timestamp();
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    std::vector<flatbuffers::Offset<fb::BranchPointer>> branchOffsets;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            auto n = builder.CreateString(bp->name()->str());
            auto h = builder.CreateString(bp->head_commit_id()->str());
            branchOffsets.push_back(fb::CreateBranchPointer(builder, n, h));
        }
    }
    auto branchesVec = builder.CreateVector(branchOffsets);

    auto newMeta = fb::CreateProjectMetadata(builder, 1, 1, nameStr, binStr, shaStr,
        created, now, curBranchStr, branchesVec, langStr, compStr,
        meta->image_base());
    builder.Finish(newMeta);

    std::ofstream out(metaPath, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
              static_cast<std::streamsize>(builder.GetSize()));
    return out.good();
}

std::string BranchManager::getCurrentBranch(const std::string& repoPath) {
    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return "";
    auto* meta = fb::GetProjectMetadata(buf.data());
    return meta->current_branch()->str();
}

std::string BranchManager::getBranchCommit(const std::string& repoPath,
                                            const std::string& branchName) {
    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return "";
    auto* meta = fb::GetProjectMetadata(buf.data());
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) {
                return bp->head_commit_id()->str();
            }
        }
    }
    return "";
}

bool BranchManager::branchExists(const std::string& repoPath,
                                  const std::string& branchName) {
    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return false;
    auto* meta = fb::GetProjectMetadata(buf.data());
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) return true;
        }
    }
    return false;
}

bool BranchManager::advanceBranch(const std::string& repoPath,
                                   const std::string& branchName,
                                   const std::string& commitId) {
    if (branchName.empty() || commitId.empty()) return false;
    if (!CommitManager::commitExists(repoPath, commitId)) return false;

    std::string metaPath = Repository::getProjectMetaPath(repoPath);
    std::vector<uint8_t> buf;
    if (!readMetaFile(metaPath, buf)) return false;

    auto* meta = fb::GetProjectMetadata(buf.data());

    bool found = false;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            if (bp->name()->str() == branchName) {
                found = true;
                break;
            }
        }
    }
    if (!found) return false;

    flatbuffers::FlatBufferBuilder builder(1024);
    auto nameStr = builder.CreateString(meta->project_name()->str());
    auto binStr = builder.CreateString(meta->binary_name()->str());
    auto shaStr = meta->binary_sha256() ? builder.CreateString(meta->binary_sha256()->str()) : 0;
    auto langStr = meta->language_id() ? builder.CreateString(meta->language_id()->str()) : 0;
    auto compStr = meta->compiler_spec_id() ? builder.CreateString(meta->compiler_spec_id()->str()) : 0;
    auto curBranchStr = builder.CreateString(meta->current_branch()->str());
    uint64_t created = meta->created_timestamp();
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    std::vector<flatbuffers::Offset<fb::BranchPointer>> branchOffsets;
    if (meta->branches()) {
        for (auto* bp : *meta->branches()) {
            auto n = builder.CreateString(bp->name()->str());
            std::string headId = (bp->name()->str() == branchName) ? commitId : bp->head_commit_id()->str();
            auto h = builder.CreateString(headId);
            branchOffsets.push_back(fb::CreateBranchPointer(builder, n, h));
        }
    }
    auto branchesVec = builder.CreateVector(branchOffsets);

    auto newMeta = fb::CreateProjectMetadata(builder, 1, 1, nameStr, binStr, shaStr,
        created, now, curBranchStr, branchesVec, langStr, compStr,
        meta->image_base());
    builder.Finish(newMeta);

    std::ofstream out(metaPath, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
              static_cast<std::streamsize>(builder.GetSize()));
    return out.good();
}

} // namespace storage
} // namespace ghidra
