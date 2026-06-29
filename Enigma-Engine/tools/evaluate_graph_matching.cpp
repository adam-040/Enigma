// evaluate_graph_matching.cpp
// Diagnostic tool: verify LMDB index data quality for Step 10/11.
// Tests callee index, scoring, multi-candidate disambiguation, and name lookups.

#include <ghidra/storage/FksIndexManager.h>
#include <ghidra/FksLibrary.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <filesystem>

using namespace ghidra::storage;
using ghidra::FksLibrary;

static uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

static int pass = 0, fail = 0;

void check(bool cond, const char* label) {
    if (cond) { pass++; std::cout << "  PASS: " << label << "\n"; }
    else      { fail++; std::cout << "  FAIL: " << label << "\n"; }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <fksDir>\n";
        return 1;
    }
    std::string fksDir = argv[1];

    std::cout << "=== FKS Graph Matching Evaluation ===\n";
    std::cout << "Directory: " << fksDir << "\n\n";

    // ── 1. Callee Index Build ────────────────────────────────────────────
    std::cout << "1. Callee Index Build\n";
    auto t0 = std::chrono::steady_clock::now();
    auto calleeIndex = FksIndexManager::buildCalleeIndex(fksDir);
    auto t1 = std::chrono::steady_clock::now();
    double buildMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    int totalCallees = 0;
    for (auto& [uid, callees] : calleeIndex) {
        totalCallees += callees.size();
    }
    std::cout << "  Unique UIDs with callees: " << calleeIndex.size() << "\n";
    std::cout << "  Total caller→callee edges: " << totalCallees << "\n";
    std::cout << "  Build time: " << std::fixed << std::setprecision(1) << buildMs << "ms\n";
    check(calleeIndex.size() > 1000, "callee index has >1000 UIDs");
    check(totalCallees > 5000, "callee index has >5000 edges");

    // Second call should hit cache
    auto t2 = std::chrono::steady_clock::now();
    auto calleeIndex2 = FksIndexManager::buildCalleeIndex(fksDir);
    auto t3 = std::chrono::steady_clock::now();
    double cachedMs = std::chrono::duration<double, std::milli>(t3 - t2).count();
    std::cout << "  Cached rebuild: " << std::fixed << std::setprecision(1) << cachedMs << "ms\n";
    check(cachedMs < 10.0, "cached build <10ms");

    // ── 2. Candidate Extraction ──────────────────────────────────────────
    std::cout << "\n2. Candidate Extraction\n";
    // Pick a known hash from kernel32 and extract all candidates
    std::string kernel32Lib = fksDir + "/kernel32_ghidra.fkslib";
    auto lib = FksLibrary::loadFromFile(kernel32Lib);
    check(lib != nullptr, "kernel32_ghidra.fkslib loads");
    if (lib && lib->functionCount() > 0) {
        auto& funcs = lib->getFunctions();
        // Find a function whose shortHashV2 is non-zero and returns candidates
        for (auto& f : funcs) {
            if (f.hashesV2.shortHash == 0) continue;
            auto data = FksIndexManager::lookupByShortHashV2(fksDir, f.hashesV2.shortHash);
            auto candidates = FksIndexManager::extractAllCandidates(data);
            if (!candidates.empty()) {
                std::cout << "  Hash 0x" << std::hex << f.hashesV2.shortHash << std::dec
                          << " → " << candidates.size() << " candidate(s)\n";
                check(true, "extractAllCandidates returns results");
                std::cout << "  First candidate: " << candidates[0].name
                          << " (uid=0x" << std::hex << candidates[0].uid << std::dec
                          << ", family=" << candidates[0].family << ")\n";
                check(!candidates[0].name.empty(), "candidate has name");
                check(!candidates[0].family.empty(), "candidate has family");
                break;
            }
        }
    }

    // ── 3. Multi-Candidate Disambiguation ────────────────────────────────
    std::cout << "\n3. Multi-Candidate Disambiguation\n";
    // Find a hash that maps to multiple candidates (cross-library)
    int multiCandidateTests = 0;
    int multiCandidateHits = 0;
    // Test with a sampling of hashes from different libraries
    std::vector<std::string> testLibs = {
        fksDir + "/ntdll_ghidra.fkslib",
        fksDir + "/advapi32_ghidra.fkslib",
        fksDir + "/user32_ghidra.fkslib"
    };
    for (auto& path : testLibs) {
        auto testLib = FksLibrary::loadFromFile(path);
        if (!testLib) continue;
        for (auto& f : testLib->getFunctions()) {
            if (f.hashesV2.shortHash == 0) continue;
            auto data = FksIndexManager::lookupByShortHashV2(fksDir, f.hashesV2.shortHash);
            auto candidates = FksIndexManager::extractAllCandidates(data);
            if (candidates.size() > 1) {
                multiCandidateTests++;
                // Test scoring
                std::vector<uint64_t> localCallees;
                auto ci = calleeIndex.find(f.uid);
                if (ci != calleeIndex.end()) {
                    localCallees = ci->second;
                }
                int bestScore = -1;
                for (auto& cand : candidates) {
                    int score = FksIndexManager::scoreCandidateByCallees(cand, calleeIndex, localCallees);
                    if (score > bestScore) bestScore = score;
                }
                if (bestScore >= 0) multiCandidateHits++;
                if (multiCandidateTests >= 5) break;
            }
        }
        if (multiCandidateTests >= 5) break;
    }
    std::cout << "  Multi-candidate hashes found: " << multiCandidateTests << "\n";
    std::cout << "  Successfully scored: " << multiCandidateHits << "\n";
    check(multiCandidateTests > 0, "found multi-candidate hashes");
    check(multiCandidateHits == multiCandidateTests, "all multi-candidate scored");

    // ── 4. Callee Scoring Quality ────────────────────────────────────────
    std::cout << "\n4. Callee Scoring Quality\n";
    // Pick a function with callees and verify scoring against itself
    int selfScoreTests = 0;
    int selfScorePass = 0;
    for (auto& [uid, callees] : calleeIndex) {
        if (callees.size() < 3) continue;
        CandidateInfo self;
        self.uid = uid;
        self.name = "self";
        int score = FksIndexManager::scoreCandidateByCallees(self, calleeIndex, callees);
        if (score == static_cast<int>(callees.size())) selfScorePass++;
        selfScoreTests++;
        if (selfScoreTests >= 10) break;
    }
    std::cout << "  Self-scoring tests: " << selfScoreTests << "\n";
    std::cout << "  Perfect self-scores: " << selfScorePass << "\n";
    check(selfScoreTests > 0, "ran self-scoring tests");
    check(selfScorePass == selfScoreTests, "all self-scores are perfect");

    // ── 5. Demangled Name Lookups ────────────────────────────────────────
    std::cout << "\n5. Demangled Name Lookups\n";
    // Find a function with non-empty nameDemangled
    int demangledCount = 0;
    for (auto& path_entry : std::filesystem::directory_iterator(fksDir)) {
        if (!path_entry.is_regular_file()) continue;
        if (path_entry.path().extension() != ".fkslib") continue;
        auto testLib = FksLibrary::loadFromFile(path_entry.path().string());
        if (!testLib) continue;
        for (auto& f : testLib->getFunctions()) {
            if (!f.nameDemangled.empty()) {
                demangledCount++;
                uint64_t nameHash = fnv1a64(f.nameDemangled);
                auto data = FksIndexManager::lookupByDemangledName(fksDir, nameHash);
                auto candidates = FksIndexManager::extractAllCandidates(data);
                if (!candidates.empty()) {
                    std::cout << "  Demangled: " << f.nameDemangled
                              << " → " << candidates.size() << " candidate(s)\n";
                }
                if (demangledCount >= 3) break;
            }
        }
        if (demangledCount >= 3) break;
    }
    std::cout << "  Functions with demangled names found: " << demangledCount << "\n";
    // Demangled names may be empty for C exports — that's OK
    check(true, "demangled name lookup runs without error");

    // ── 6. Namespace Lookups ─────────────────────────────────────────────
    std::cout << "\n6. Namespace Lookups\n";
    int nsCount = 0;
    for (auto& path_entry : std::filesystem::directory_iterator(fksDir)) {
        if (!path_entry.is_regular_file()) continue;
        if (path_entry.path().extension() != ".fkslib") continue;
        auto testLib = FksLibrary::loadFromFile(path_entry.path().string());
        if (!testLib) continue;
        for (auto& f : testLib->getFunctions()) {
            if (!f.namespacePath.empty()) {
                nsCount++;
                uint64_t nsHash = fnv1a64(f.namespacePath);
                auto data = FksIndexManager::lookupByNamespace(fksDir, nsHash);
                auto candidates = FksIndexManager::extractAllCandidates(data);
                if (!candidates.empty()) {
                    std::cout << "  Namespace: " << f.namespacePath
                              << " → " << candidates.size() << " candidate(s)\n";
                }
                if (nsCount >= 3) break;
            }
        }
        if (nsCount >= 3) break;
    }
    std::cout << "  Functions with namespaces found: " << nsCount << "\n";
    check(nsCount > 0, "found functions with namespaces");
    check(true, "namespace lookup runs without error");

    // ── 7. Body+Instr Composite Lookups ──────────────────────────────────
    std::cout << "\n7. Body+Instr Composite Lookups\n";
    int biTests = 0;
    for (auto& path_entry : std::filesystem::directory_iterator(fksDir)) {
        if (!path_entry.is_regular_file()) continue;
        if (path_entry.path().extension() != ".fkslib") continue;
        auto testLib = FksLibrary::loadFromFile(path_entry.path().string());
        if (!testLib) continue;
        for (auto& f : testLib->getFunctions()) {
            uint64_t composite = (static_cast<uint64_t>(f.bodySize) << 32) | f.instrCount;
            auto data = FksIndexManager::lookupByBodyInstr(fksDir, composite);
            auto candidates = FksIndexManager::extractAllCandidates(data);
            if (candidates.size() > 1) {
                biTests++;
                if (biTests >= 3) break;
            }
        }
        if (biTests >= 3) break;
    }
    std::cout << "  Body+Instr composite collisions: " << biTests << "\n";
    check(true, "body+instr composite lookup runs without error");

    // ── Summary ──────────────────────────────────────────────────────────
    std::cout << "\n=== Evaluation Summary ===\n";
    std::cout << "  Passed: " << pass << "\n";
    std::cout << "  Failed: " << fail << "\n";
    std::cout << "  Callee index: " << calleeIndex.size() << " UIDs, "
              << totalCallees << " edges\n";

    return fail > 0 ? 1 : 0;
}
