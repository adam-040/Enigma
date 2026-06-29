#include <ghidra/FksLibrary.h>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>

namespace fs = std::filesystem;

int main() {
    fs::path fidDir("C:/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/fid");

    std::vector<fs::path> fksFiles;
    for (auto& entry : fs::directory_iterator(fidDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".fkslib")
            fksFiles.push_back(entry.path());
    }
    std::sort(fksFiles.begin(), fksFiles.end());

    struct Row {
        std::string filename;
        int functions;
        int relations;
        int functions_with_signature;
        int functions_with_namespace;
    };
    std::vector<Row> rows;

    int totalFunctions = 0;
    int totalRelations = 0;
    int totalFuncsWithSig = 0;
    int totalFuncsWithNs = 0;
    int zeroRelationCount = 0;
    int errorCount = 0;

    for (auto& path : fksFiles) {
        std::string filename = path.filename().string();
        try {
            auto lib = ghidra::FksLibrary::loadFromFile(path.string());
            if (!lib) {
                std::cerr << "  ERROR: loadFromFile returned nullptr for " << filename << "\n";
                ++errorCount;
                continue;
            }

            const auto& funcs = lib->getFunctions();
            const auto& rels  = lib->getRelations();

            int withSig = 0;
            int withNs  = 0;
            for (const auto& f : funcs) {
                if (!f.signature.empty()) ++withSig;
                if (!f.namespacePath.empty()) ++withNs;
            }

            rows.push_back({filename, static_cast<int>(funcs.size()), static_cast<int>(rels.size()), withSig, withNs});

            totalFunctions += static_cast<int>(funcs.size());
            totalRelations += static_cast<int>(rels.size());
            totalFuncsWithSig += withSig;
            totalFuncsWithNs += withNs;
            if (rels.empty()) ++zeroRelationCount;

        } catch (const std::exception& e) {
            std::cerr << "  ERROR loading " << filename << ": " << e.what() << "\n";
            ++errorCount;
        }
    }

    // Print table
    std::cout << std::left
              << std::setw(40) << "Filename"
              << std::right
              << std::setw(12) << "Functions"
              << std::setw(12) << "Relations"
              << std::setw(8) << "WithSig"
              << std::setw(8) << "WithNs"
              << "\n";
    std::cout << std::string(80, '-') << "\n";

    for (const auto& r : rows) {
        std::cout << std::left
                  << std::setw(40) << r.filename
                  << std::right
                  << std::setw(12) << r.functions
                  << std::setw(12) << r.relations
                  << std::setw(8) << r.functions_with_signature
                  << std::setw(8) << r.functions_with_namespace
                  << "\n";
    }

    std::cout << std::string(80, '=') << "\n";
    std::cout << std::left
              << std::setw(40) << "TOTALS"
              << std::right
              << std::setw(12) << totalFunctions
              << std::setw(12) << totalRelations
              << std::setw(8) << totalFuncsWithSig
              << std::setw(8) << totalFuncsWithNs
              << "\n";

    std::cout << "\nFiles scanned:  " << fksFiles.size() << "\n";
    std::cout << "Files w/ 0 rels: " << zeroRelationCount << "\n";
    std::cout << "Errors:          " << errorCount << "\n";

    return 0;
}
