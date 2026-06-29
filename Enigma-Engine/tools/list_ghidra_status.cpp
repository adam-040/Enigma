#include <ghidra/FksLibrary.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

int main() {
    fs::path fidDir("C:\\Users\\pc\\Desktop\\Enigma IDE Local\\Enigma-Engine\\fid");

    std::vector<fs::path> ghidraFiles;
    for (auto& entry : fs::directory_iterator(fidDir)) {
        if (entry.is_regular_file()) {
            auto stem = entry.path().stem().string();
            if (stem.size() > 7 && stem.substr(stem.size() - 7) == "_ghidra")
                ghidraFiles.push_back(entry.path());
        }
    }
    std::sort(ghidraFiles.begin(), ghidraFiles.end());

    std::cout << "=== Ghidra FKS Libraries Status ===\n\n";

    int totalFiles = 0;
    int needsExport = 0;

    for (auto& path : ghidraFiles) {
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

        int funcCount = lib->functionCount();
        int relCount = static_cast<int>(lib->getRelations().size());

        std::cout << filename
                  << "  functions=" << funcCount
                  << "  relations=" << relCount;

        if (relCount == 0) {
            std::cout << "  [NEEDS RE-EXPORT]";
            ++needsExport;
        }

        std::cout << "\n";
    }

    std::cout << "\n=== Summary ===\n";
    std::cout << "Total *_ghidra.fkslib files: " << totalFiles << "\n";
    std::cout << "Files needing re-export:     " << needsExport << "\n";

    return 0;
}
