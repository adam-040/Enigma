/* ###
 * IP: GHIDRA
 *
 * FksRepository — path helpers for the FKS directory layout.
 */
#include <ghidra/storage/FksRepository.h>
#include <filesystem>
#include <cstdlib>

namespace ghidra {
namespace storage {

namespace fs = std::filesystem;

std::string FksRepository::getFksDirFromEnv() {
    // Priority: ENIGMA_FKS_DIR env var > compile-time default
    if (const char* env = std::getenv("ENIGMA_FKS_DIR"))
        return std::string(env);
#ifndef ENIGMA_FKS_DIR
#define ENIGMA_FKS_DIR ""
#endif
    return ENIGMA_FKS_DIR;
}

std::string FksRepository::getFksDir(const std::string& installRoot) {
    return installRoot + "/fid";
}

std::string FksRepository::getIndexDir(const std::string& fksDir) {
    return fksDir + "/index/lmdb";
}

std::string FksRepository::getManifestPath(const std::string& fksDir) {
    return fksDir + "/manifest.json";
}

bool FksRepository::ensureIndexDir(const std::string& fksDir) {
    std::error_code ec;
    fs::create_directories(getIndexDir(fksDir), ec);
    return !ec;
}

} // namespace storage
} // namespace ghidra
