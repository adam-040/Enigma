/// enigma_fks_export_hashes.cpp
/// Reads all .fkslib files from a fid/ directory and outputs C++ code
/// for KnownFunctionHashes entries (hash→name pairs).
/// Usage: enigma_fks_export_hashes [<fid_dir>]

#include <ghidra/FksLibrary.h>
#include <ghidra/storage/FksRepository.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <set>

using namespace ghidra;

int main(int argc, char* argv[]) {
    std::string fksDir;

    if (argc >= 2) {
        fksDir = argv[1];
    } else {
        fksDir = storage::FksRepository::getFksDirFromEnv();
    }

    if (fksDir.empty()) {
        std::cerr << "Usage: enigma_fks_export_hashes <fid_dir>\n";
        return 1;
    }

    if (!std::filesystem::exists(fksDir)) {
        std::cerr << "FKS directory does not exist: " << fksDir << "\n";
        return 1;
    }

    // Collect all unique hash→name pairs across all libraries
    struct HashEntry {
        uint64_t hash;
        std::string name;
        std::string library;
    };

    std::vector<HashEntry> entries;
    std::set<uint64_t> seenHashes;  // deduplicate by hash

    for (auto& fileEntry : std::filesystem::directory_iterator(fksDir)) {
        if (!fileEntry.is_regular_file()) continue;
        if (fileEntry.path().extension() != ".fkslib") continue;

        auto lib = FksLibrary::loadFromFile(fileEntry.path().string());
        if (!lib) continue;

        std::string libName = lib->getMeta().family;
        for (auto& func : lib->getFunctions()) {
            if (func.hashes.fullHash == 0) continue;
            if (func.name.empty()) continue;

            // Only take first occurrence of each hash (highest priority library)
            if (seenHashes.count(func.hashes.fullHash)) continue;
            seenHashes.insert(func.hashes.fullHash);

            entries.push_back({func.hashes.fullHash, func.name, libName});
        }
    }

    // Output C++ code
    std::cout << "// Auto-generated from FKS knowledge base (" << entries.size() << " entries)\n";
    std::cout << "// Source libraries: ";
    std::set<std::string> libs;
    for (auto& e : entries) libs.insert(e.library);
    bool first = true;
    for (auto& l : libs) {
        if (!first) std::cout << ", ";
        std::cout << l;
        first = false;
    }
    std::cout << "\n\n";

    for (auto& e : entries) {
        std::cout << "    add(0x" << std::hex << e.hash << "ULL, \"" << e.name << "\");\n";
    }

    std::cerr << "Exported " << entries.size() << " hash→name entries.\n";
    return 0;
}
