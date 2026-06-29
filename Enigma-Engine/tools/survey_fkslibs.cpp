#include <ghidra/FksLibrary.h>
#include <flatbuffers/flatbuffers.h>
#include "fks_generated.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: survey_fkslibs <directory>\n";
        return 1;
    }

    fs::path dir(argv[1]);
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

    std::cout << "=== FKS Library Survey ===\n\n";

    int v2Count = 0, v3Count = 0, errorCount = 0;

    for (auto& path : fksFiles) {
        std::string filename = path.filename().string();

        // Load raw bytes to read schema_version directly from FlatBuffer root
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in.is_open()) {
            std::cerr << "  ERROR: cannot open " << filename << "\n";
            ++errorCount;
            continue;
        }
        size_t fileSize = static_cast<size_t>(in.tellg());
        in.seekg(0);
        std::vector<uint8_t> buf(fileSize);
        in.read(reinterpret_cast<char*>(buf.data()), fileSize);
        if (!in) {
            std::cerr << "  ERROR: read failed " << filename << "\n";
            ++errorCount;
            continue;
        }

        // Read schema_version from the raw FlatBuffer
        int schemaVersion = 0;
        {
            flatbuffers::Verifier verifier(buf.data(), buf.size());
            if (!verifier.VerifyBuffer<fbschema::FksLibrary>(nullptr)) {
                std::cerr << "  ERROR: verification failed " << filename << "\n";
                ++errorCount;
                continue;
            }
            auto root = flatbuffers::GetRoot<fbschema::FksLibrary>(buf.data());
            schemaVersion = root->schema_version();
        }

        // Load via FksLibrary for the structured data
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
        const auto& meta  = lib->getMeta();

        std::cout << filename
                  << "  schema=" << schemaVersion
                  << "  funcs=" << funcs.size()
                  << "  rels=" << rels.size();

        if (!meta.family.empty())
            std::cout << "  family=" << meta.family;
        if (!meta.compiler.empty())
            std::cout << "  compiler=" << meta.compiler;

        if (!funcs.empty()) {
            const auto& f = funcs[0];
            std::cout << "  [0]name=" << f.name
                      << " demangled_empty=" << (f.nameDemangled.empty() ? "Y" : "N")
                      << " ns_empty=" << (f.namespacePath.empty() ? "Y" : "N")
                      << " sig_empty=" << (f.signature.empty() ? "Y" : "N");
        }

        std::cout << "\n";

        if (schemaVersion == 2) ++v2Count;
        else if (schemaVersion == 3) ++v3Count;
    }

    std::cout << "\n=== Summary ===\n";
    std::cout << "Total files:   " << fksFiles.size() << "\n";
    std::cout << "Schema v2:     " << v2Count << "\n";
    std::cout << "Schema v3:     " << v3Count << "\n";
    std::cout << "Errors:        " << errorCount << "\n";

    return 0;
}
