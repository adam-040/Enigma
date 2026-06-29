// evaluate_cross_library.cpp
// Moves one .fkslib out, rebuilds index, tests ALL its functions
// against remaining libraries to measure cross-library ID rate.

#include <ghidra/storage/FksIndexManager.h>
#include <ghidra/FksLibrary.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/verifier.h>
#include "fks_generated.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <cstdint>

using namespace ghidra::storage;
using ghidra::FksLibrary;

static std::string extractFirst(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    auto verifier = flatbuffers::Verifier(data.data(), data.size());
    if (!verifier.VerifyBuffer<fbschema::FkCandidateList>()) return "";
    auto* list = flatbuffers::GetRoot<fbschema::FkCandidateList>(data.data());
    if (!list || !list->candidates() || list->candidates()->size() == 0) return "";
    auto* first = list->candidates()->Get(0);
    if (!first || !first->name()) return "";
    return first->name()->str();
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <fksDir> <target.fkslib> <exclude_family>\n";
        return 1;
    }
    std::string fksDir = argv[1];
    std::string targetPath = argv[2];
    std::string excludeFamily = argv[3];

    auto targetLib = FksLibrary::loadFromFile(targetPath);
    if (!targetLib) { std::cerr << "Cannot load " << targetPath << "\n"; return 1; }
    auto& meta = targetLib->getMeta();
    auto& funcs = targetLib->getFunctions();
    auto& rels  = targetLib->getRelations();

    std::cout << "=== Cross-Library Matching Test ===\n";
    std::cout << "Target:  " << meta.family << " (" << funcs.size() << " functions, "
              << rels.size() << " relations)\n";
    std::cout << "Index excludes: " << excludeFamily << "\n\n";

    // Build callee index from the (already rebuilt) index
    auto calleeIndex = FksIndexManager::buildCalleeIndex(fksDir);

    // For each function, try to identify using all strategies
    // Count by primary matching strategy
    int total = funcs.size();
    int viaAddr = 0, viaV2 = 0, viaV1 = 0, viaBI = 0, viaCallee = 0;
    int multiCandidateHit = 0;
    int v2Correct = 0, v2Total = 0;

    for (auto& f : funcs) {
        std::string matched;

        // Strategy 1: Address-based
        if (matched.empty() && f.virtualAddress > 0) {
            auto data = FksIndexManager::lookupByAddress(fksDir, meta.family, f.virtualAddress);
            matched = extractFirst(data);
            if (!matched.empty()) viaAddr++;
        }

        // Strategy 2: V2 hashes
        if (matched.empty() && f.hashesV2.shortHash != 0) {
            auto data = FksIndexManager::lookupByShortHashV2(fksDir, f.hashesV2.shortHash);
            matched = extractFirst(data);
        }
        if (matched.empty() && f.hashesV2.fullHash != 0 && f.hashesV2.fullHash != f.hashesV2.shortHash) {
            auto data = FksIndexManager::lookupByFullHashV2(fksDir, f.hashesV2.fullHash);
            matched = extractFirst(data);
        }
        if (matched.empty() && f.hashesV2.mnemHash != 0) {
            auto data = FksIndexManager::lookupByMnemHashV2(fksDir, f.hashesV2.mnemHash);
            matched = extractFirst(data);
        }
        if (matched.empty() && f.hashesV2.callHash != 0) {
            auto data = FksIndexManager::lookupByCallHashV2(fksDir, f.hashesV2.callHash);
            matched = extractFirst(data);
        }
            if (!matched.empty()) {
                viaV2++;
                v2Total++;
                if (matched == f.name) v2Correct++;
            }

        // Strategy 3: V1 hashes
        if (matched.empty() && f.hashes.fullHash != 0) {
            auto data = FksIndexManager::lookupByFullHash(fksDir, f.hashes.fullHash);
            matched = extractFirst(data);
        }
        if (matched.empty() && f.hashes.shortHash != 0 && f.hashes.shortHash != f.hashes.fullHash) {
            auto data = FksIndexManager::lookupByShortHash(fksDir, f.hashes.shortHash);
            matched = extractFirst(data);
        }
        if (matched.empty() && f.hashes.callHash != 0) {
            auto data = FksIndexManager::lookupByCallHash(fksDir, f.hashes.callHash);
            matched = extractFirst(data);
        }
        if (!matched.empty() && viaV2 == 0) { viaV1++; }

        // Strategy 4: Body+instr composite
        if (matched.empty() && f.bodySize > 0 && f.instrCount > 0) {
            uint64_t composite = (static_cast<uint64_t>(f.bodySize) << 32) | f.instrCount;
            auto data = FksIndexManager::lookupByBodyInstr(fksDir, composite);
            matched = extractFirst(data);
            if (!matched.empty()) viaBI++;
        }

        // Strategy 5: Callee-set scoring
        if (matched.empty() && !rels.empty()) {
            // Build local callee UID set from relations
            std::vector<uint64_t> calleeUids;
            for (auto& rel : rels) {
                if (rel.callerIndex < funcs.size() && funcs[rel.callerIndex].uid == f.uid
                    && rel.calleeIndex < funcs.size()) {
                    calleeUids.push_back(funcs[rel.calleeIndex].uid);
                }
            }
            if (!calleeUids.empty()) {
                // Try each hash type for multi-candidate scoring
                struct HashEntry { uint64_t hash; uint8_t prefix; };
                HashEntry tries[] = {
                    {f.hashesV2.shortHash, 0x21}, {f.hashesV2.fullHash, 0x20},
                    {f.hashesV2.mnemHash, 0x22}, {f.hashesV2.callHash, 0x23},
                    {f.hashes.fullHash, 0x10}, {f.hashes.shortHash, 0x11},
                    {f.hashes.callHash, 0x13}
                };
                for (auto& t : tries) {
                    if (t.hash == 0) continue;
                    auto data = FksIndexManager::lookupByHash(fksDir, t.prefix, t.hash);
                    auto candidates = FksIndexManager::extractAllCandidates(data);
                    if (candidates.size() <= 1) continue;
                    multiCandidateHit++;
                    std::sort(calleeUids.begin(), calleeUids.end());
                    const CandidateInfo* best = nullptr;
                    int bestScore = -1;
                    for (auto& cand : candidates) {
                        int score = FksIndexManager::scoreCandidateByCallees(cand, calleeIndex, calleeUids);
                        if (score > bestScore) { bestScore = score; best = &cand; }
                    }
                    if (best && bestScore > 0) {
                        matched = best->name;
                        viaCallee++;
                        break;
                    }
                }
            }
        }
    }

    int totalMatched = viaAddr + viaV2 + viaV1 + viaBI + viaCallee;
    auto pct = [total](int n) -> double { return total > 0 ? 100.0 * n / total : 0.0; };

    std::cout << std::left << std::setw(35) << "Strategy" << std::right << std::setw(8) << "Count" << std::setw(10) << "Rate\n";
    std::cout << std::string(53, '-') << "\n";
    std::cout << std::left << std::setw(35) << "Functions tested" << std::right << std::setw(8) << total << "\n";
    std::cout << std::left << std::setw(35) << "Address-based" << std::right << std::setw(8) << viaAddr << std::setw(9) << std::fixed << std::setprecision(1) << pct(viaAddr) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 hash match (instr-aware)" << std::right << std::setw(8) << viaV2 << std::setw(9) << pct(viaV2) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 hash match (raw bytes)" << std::right << std::setw(8) << viaV1 << std::setw(9) << pct(viaV1) << "%\n";
    std::cout << std::left << std::setw(35) << "Body+instr composite" << std::right << std::setw(8) << viaBI << std::setw(9) << pct(viaBI) << "%\n";
    std::cout << std::left << std::setw(35) << "Callee-set (Step 10/11)" << std::right << std::setw(8) << viaCallee << std::setw(9) << pct(viaCallee) << "%\n";
    std::cout << std::string(53, '-') << "\n";
    std::cout << std::left << std::setw(35) << "Multi-candidate collisions hit" << std::right << std::setw(8) << multiCandidateHit << "\n";
    std::cout << std::left << std::setw(35) << "V2 match accuracy (exact name)" << std::right << std::setw(8) << v2Correct << "/" << v2Total << std::setw(9) << (v2Total>0 ? pct(v2Correct) : 0.0) << "%\n";
    std::cout << std::left << std::setw(35) << "TOTAL CROSS-LIBRARY ID RATE" << std::right << std::setw(8) << totalMatched << std::setw(9) << pct(totalMatched) << "%\n";
    return 0;
}
