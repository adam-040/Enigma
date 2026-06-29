#include <ghidra/FksLibrary.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>

namespace fs = std::filesystem;

struct LibStats {
    std::string filename;
    int functionCount;
    int relationCount;
    int demangledCount;
    int namespaceCount;
    int signatureCount;
};

int main(int argc, char* argv[]) {
    fs::path dir = (argc >= 2) ? fs::path(argv[1]) : fs::path("C:/Users/pc/Desktop/Enigma IDE Local/Enigma-Engine/fid");

    if (!fs::is_directory(dir)) {
        std::cerr << "Error: " << dir << " is not a directory\n";
        return 1;
    }

    std::vector<fs::path> fksFiles;
    for (auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".fkslib")
            fksFiles.push_back(entry.path());
    }
    std::sort(fksFiles.begin(), fksFiles.end());

    std::vector<LibStats> stats;
    int errorCount = 0;

    for (auto& path : fksFiles) {
        std::string filename = path.filename().string();

        std::unique_ptr<ghidra::FksLibrary> lib;
        try {
            lib = ghidra::FksLibrary::loadFromFile(path.string());
        } catch (const std::exception& e) {
            std::cerr << "  ERROR loading " << filename << ": " << e.what() << "\n";
            ++errorCount;
            continue;
        }

        const auto& funcs = lib->getFunctions();
        const auto& rels  = lib->getRelations();

        int demangled = 0, ns = 0, sig = 0;
        for (const auto& f : funcs) {
            if (!f.nameDemangled.empty()) ++demangled;
            if (!f.namespacePath.empty()) ++ns;
            if (!f.signature.empty()) ++sig;
        }

        stats.push_back({filename, static_cast<int>(funcs.size()), static_cast<int>(rels.size()), demangled, ns, sig});
    }

    std::sort(stats.begin(), stats.end(), [](const LibStats& a, const LibStats& b) {
        return a.relationCount > b.relationCount;
    });

    // Print table
    std::cout << std::left
              << std::setw(35) << "Filename"
              << std::right
              << std::setw(10) << "Funcs"
              << std::setw(10) << "Rels"
              << std::setw(12) << "Demangled"
              << std::setw(12) << "Namespace"
              << std::setw(12) << "Signature"
              << "\n";
    std::cout << std::string(91, '-') << "\n";

    int totalFuncs = 0, totalRels = 0, totalDem = 0, totalNs = 0, totalSig = 0;
    for (const auto& s : stats) {
        std::cout << std::left  << std::setw(35) << s.filename
                  << std::right
                  << std::setw(10) << s.functionCount
                  << std::setw(10) << s.relationCount
                  << std::setw(12) << s.demangledCount
                  << std::setw(12) << s.namespaceCount
                  << std::setw(12) << s.signatureCount
                  << "\n";
        totalFuncs += s.functionCount;
        totalRels  += s.relationCount;
        totalDem   += s.demangledCount;
        totalNs    += s.namespaceCount;
        totalSig   += s.signatureCount;
    }

    std::cout << std::string(91, '=') << "\n";
    std::cout << std::left  << std::setw(35) << "TOTAL"
              << std::right
              << std::setw(10) << totalFuncs
              << std::setw(10) << totalRels
              << std::setw(12) << totalDem
              << std::setw(12) << totalNs
              << std::setw(12) << totalSig
              << "\n\n";

    std::cout << "Files scanned: " << stats.size() << "  Errors: " << errorCount << "\n";

    return 0;
}
