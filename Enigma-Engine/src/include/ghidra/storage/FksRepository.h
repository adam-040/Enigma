/* ###
 * IP: GHIDRA
 *
 * FksRepository — path helpers for the FKS directory layout.
 */
#pragma once

#include <string>

namespace ghidra {
namespace storage {

class FksRepository {
public:
    static std::string getFksDir(const std::string& installRoot);
    static std::string getIndexDir(const std::string& fksDir);
    static std::string getManifestPath(const std::string& fksDir);
    static bool ensureIndexDir(const std::string& fksDir);
    static std::string getFksDirFromEnv();
};

} // namespace storage
} // namespace ghidra
