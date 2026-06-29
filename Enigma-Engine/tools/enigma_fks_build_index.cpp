/// enigma_fks_build_index.cpp
/// Scans a fid/ directory for .fkslib files and rebuilds the LMDB index.
/// Usage: enigma_fks_build_index [<fid_dir>]
/// If no directory is specified, uses ENIGMA_FKS_DIR env var or compile-time default.

#include <ghidra/storage/FksIndexManager.h>
#include <ghidra/storage/FksRepository.h>
#include <iostream>
#include <string>
#include <filesystem>

using namespace ghidra;
using namespace ghidra::storage;

int main(int argc, char* argv[]) {
    std::string fksDir;

    if (argc >= 2) {
        fksDir = argv[1];
    } else {
        fksDir = FksRepository::getFksDirFromEnv();
    }

    if (fksDir.empty()) {
        std::cerr << "Usage: enigma_fks_build_index <fid_dir>\n";
        std::cerr << "Or set ENIGMA_FKS_DIR environment variable.\n";
        return 1;
    }

    if (!std::filesystem::exists(fksDir)) {
        std::cerr << "FKS directory does not exist: " << fksDir << "\n";
        return 1;
    }

    // Clear existing index
    FksIndexManager::clear(fksDir);

    // Rebuild from all .fkslib files
    int totalFunctions = FksIndexManager::rebuildFromFksDir(fksDir);

    if (totalFunctions < 0) {
        std::cerr << "Index rebuild failed.\n";
        return 1;
    }

    // Count .fkslib files
    int libCount = 0;
    for (auto& entry : std::filesystem::directory_iterator(fksDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".fkslib") {
            libCount++;
        }
    }

    bool exists = FksIndexManager::indexExists(fksDir);

    std::cerr << "FKS index rebuilt successfully.\n";
    std::cerr << "  Libraries:  " << libCount << "\n";
    std::cerr << "  Functions:  " << totalFunctions << "\n";
    std::cerr << "  Index:      " << (exists ? "created" : "FAILED") << "\n";

    return 0;
}
