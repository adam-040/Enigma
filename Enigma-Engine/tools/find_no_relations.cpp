#include <ghidra/FksLibrary.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

int main() {
    fs::path fidDir("C:\\Users\\pc\\Desktop\\Enigma IDE Local\\Enigma-Engine\\fid");
    if (!fs::is_directory(fidDir)) {
        std::cerr << "Error: " << fidDir << " is not a directory\n";
        return 1;
    }

    std::vector<fs::path> fksFiles;
    for (auto& entry : fs::directory_iterator(fidDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".fkslib")
            fksFiles.push_back(entry.path());
    }
    std::sort(fksFiles.begin(), fksFiles.end());

    std::cout << "=== FKS Libraries with NO Relations ===\n\n";

    int totalFiles = 0;
    int noRelCount = 0;

    for (auto& path : fksFiles) {
        ++totalFiles;
        std::string filename = path.filename().string();

        std::unique_ptr<ghidra::FksLibrary> lib;
        try {
            lib = ghidra::FksLibrary::loadFromFile(path.string());
        } catch (const std::exception& e) {
            std::cerr << "  ERROR loading " << filename << ": " << e.what() << "\n";
            continue;
        }

        if (!lib) {
            std::cerr << "  ERROR: loadFromFile returned null for " << filename << "\n";
            continue;
        }

        const auto& rels = lib->getRelations();
        if (!rels.empty())
            continue;

        ++noRelCount;

        const auto& funcs = lib->getFunctions();
        int funcCount = lib->functionCount();

        bool anyNonEmptySig = false;
        for (const auto& f : funcs) {
            if (!f.signature.empty()) {
                anyNonEmptySig = true;
                break;
            }
        }

        std::cout << filename
                  << "  functions=" << funcCount
                  << "  hasNonEmptySignature=" << (anyNonEmptySig ? "YES" : "NO")
                  << "\n";
    }

    std::cout << "\n=== Summary ===\n";
    std::cout << "Total .fkslib files: " << totalFiles << "\n";
    std::cout << "Files with 0 relations: " << noRelCount << "\n";

    return 0;
}
