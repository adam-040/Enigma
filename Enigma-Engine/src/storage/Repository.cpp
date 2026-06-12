#include <ghidra/storage/Repository.h>
#include "project_generated.h"
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <ctime>

namespace ghidra {
namespace storage {

namespace fb = fbschema;
namespace fs = std::filesystem;

bool Repository::create(const std::string& path,
                        const std::string& projectName,
                        const std::string& binaryName,
                        const std::string& binarySha256,
                        const std::string& languageId,
                        const std::string& compilerSpecId,
                        uint64_t imageBase) {
    if (!fs::create_directories(path + "/metadata")) return false;
    if (!fs::create_directories(path + "/working")) return false;
    if (!fs::create_directories(path + "/commits")) return false;
    if (!fs::create_directories(path + "/index/lmdb")) return false;
    if (!fs::create_directories(path + "/binary")) return false;

    flatbuffers::FlatBufferBuilder builder(1024);
    auto projName = builder.CreateString(projectName);
    auto binName = builder.CreateString(binaryName);
    auto binSha256 = builder.CreateString(binarySha256);
    auto langId = builder.CreateString(languageId);
    auto compId = builder.CreateString(compilerSpecId);
    auto currentBranch = builder.CreateString("main");
    auto mainBranchPtr = fb::CreateBranchPointer(builder,
        builder.CreateString("main"), builder.CreateString(""));
    std::vector<flatbuffers::Offset<fb::BranchPointer>> branchesVec = {mainBranchPtr};
    auto branches = builder.CreateVector(branchesVec);
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    auto meta = fb::CreateProjectMetadata(builder, 1, 1, projName, binName, binSha256,
        now, now, currentBranch, branches, langId, compId, imageBase);
    builder.Finish(meta);

    std::ofstream out(getProjectMetaPath(path), std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(builder.GetBufferPointer()), builder.GetSize());
    return out.good();
}

bool Repository::open(const std::string& path) {
    if (!fs::exists(path + "/metadata")) return false;
    if (!fs::exists(path + "/working")) return false;
    if (!fs::exists(path + "/commits")) return false;
    if (!fs::exists(path + "/index/lmdb")) return false;
    if (!fs::exists(path + "/binary")) return false;
    std::string metaPath = getProjectMetaPath(path);
    if (!fs::exists(metaPath)) return false;

    std::ifstream in(metaPath, std::ios::binary | std::ios::ate);
    if (!in) return false;
    size_t size = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    if (!in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size)))
        return false;

    flatbuffers::Verifier verifier(buf.data(), buf.size());
    return fb::VerifyProjectMetadataBuffer(verifier);
}

std::string Repository::getMetadataDir(const std::string& repoPath) {
    return repoPath + "/metadata";
}

std::string Repository::getWorkingDir(const std::string& repoPath) {
    return repoPath + "/working";
}

std::string Repository::getCommitsDir(const std::string& repoPath) {
    return repoPath + "/commits";
}

std::string Repository::getIndexDir(const std::string& repoPath) {
    return repoPath + "/index/lmdb";
}

std::string Repository::getBinaryDir(const std::string& repoPath) {
    return repoPath + "/binary";
}

std::string Repository::getProjectMetaPath(const std::string& repoPath) {
    return repoPath + "/metadata/project.meta";
}

std::string Repository::getBranchesMetaPath(const std::string& repoPath) {
    return repoPath + "/metadata/branches.meta";
}

std::string Repository::getWorkingSnapshotPath(const std::string& repoPath) {
    return repoPath + "/working/working.fbs";
}

std::string Repository::getCommitDir(const std::string& repoPath, const std::string& commitId) {
    return repoPath + "/commits/" + commitId;
}

std::string Repository::getCommitSnapshotPath(const std::string& repoPath, const std::string& commitId) {
    return repoPath + "/commits/" + commitId + "/snapshot.fbs";
}

std::string Repository::getCommitChangeSetPath(const std::string& repoPath, const std::string& commitId) {
    return repoPath + "/commits/" + commitId + "/changeset.fbs";
}

std::string Repository::getCommitMetaPath(const std::string& repoPath, const std::string& commitId) {
    return repoPath + "/commits/" + commitId + "/commit.meta";
}

} // namespace storage
} // namespace ghidra
