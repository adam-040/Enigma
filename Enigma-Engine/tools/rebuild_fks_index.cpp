/**
 * rebuild_fks_index.cpp
 * Rebuilds the FKS LMDB index (data.mdb) from all *.fkslib files in a directory.
 * Usage: enigma_rebuild_fks_index <fid_dir>
 *   e.g: enigma_rebuild_fks_index ../fid
 */
#include <ghidra/FksLibrary.h>
#include <ghidra/storage/FksIndexManager.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    std::string fidDir = (argc > 1) ? argv[1] : "../fid";

    if (!fs::exists(fidDir)) {
        std::cerr << "[ERROR] FID directory not found: " << fidDir << "\n";
        return 1;
    }

    // Collect all .fkslib files
    std::vector<fs::path> libs;
    for (auto& entry : fs::directory_iterator(fidDir)) {
        if (entry.path().extension() == ".fkslib")
            libs.push_back(entry.path());
    }
    std::sort(libs.begin(), libs.end());

    std::cout << "[rebuild_fks_index] Found " << libs.size() << " .fkslib files in: " << fidDir << "\n";
    std::cout << "[rebuild_fks_index] Clearing existing index...\n";
    ghidra::storage::FksIndexManager::clear(fidDir);

    int ok = 0, fail = 0;
    for (auto& libPath : libs) {
        auto lib = ghidra::FksLibrary::loadFromFile(libPath.string());
        if (!lib) {
            std::cerr << "  [SKIP] Failed to load: " << libPath.filename() << "\n";
            ++fail;
            continue;
        }
        bool indexed = ghidra::storage::FksIndexManager::indexLibrary(fidDir, *lib);
        if (indexed) {
            std::cout << "  [OK]   " << libPath.filename().string()
                      << " (" << lib->functionCount() << " funcs)\n";
            ++ok;
        } else {
            std::cerr << "  [FAIL] " << libPath.filename().string() << "\n";
            ++fail;
        }
    }

    std::cout << "\n[rebuild_fks_index] Done. Indexed: " << ok << " | Failed: " << fail << "\n";
    return fail > 0 ? 1 : 0;
}
