// evaluate_id_rate_from_fkslib.cpp
// Reads a .fkslib file, matches each function against LMDB index, reports ID rates.

#include <ghidra/storage/FksIndexManager.h>
#include <ghidra/FksLibrary.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/verifier.h>
#include "fks_generated.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

using namespace ghidra::storage;
using ghidra::FksLibrary;

static std::string extractName(const std::vector<uint8_t>& data) {
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
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <fksDir> <library.fkslib>\n";
        return 1;
    }
    std::string fksDir = argv[1];
    std::string libPath = argv[2];

    auto lib = FksLibrary::loadFromFile(libPath);
    if (!lib) { std::cerr << "Cannot load " << libPath << "\n"; return 1; }

    auto& meta = lib->getMeta();
    auto& funcs = lib->getFunctions();
    auto& rels  = lib->getRelations();

    std::cout << "=== Identification Rate Evaluation ===\n";
    std::cout << "Library:   " << meta.family << " (" << meta.compiler << " " << meta.version << ")\n";
    std::cout << "Functions: " << funcs.size() << "\n";
    std::cout << "Relations: " << rels.size() << "\n\n";

    // Build callee index
    auto calleeIndex = FksIndexManager::buildCalleeIndex(fksDir);

    // Count pre-named (non-auto-generated names)
    int preNamed = 0;
    for (auto& f : funcs) {
        if (f.name.find("FUN_") != 0 && f.name.find("sub_") != 0 && f.name.find("entry") != 0) {
            preNamed++;
        }
    }

    // Matching simulation: for each function, try all strategies
    int total = funcs.size();
    int addrMatch = 0, v2ShortMatch = 0, v2FullMatch = 0, v2MnemMatch = 0, v2CallMatch = 0;
    int v1FullMatch = 0, v1ShortMatch = 0, v1CallMatch = 0;
    int biMatch = 0, calleeMatch = 0;
    int alreadyNamed = 0;

    for (auto& f : funcs) {
        bool isAutoGen = (f.name.find("FUN_") == 0 || f.name.find("sub_") == 0 || f.name == "entry");
        if (!isAutoGen) { alreadyNamed++; continue; }

        std::string matchedName;

        // Strategy 1: Address-based
        if (matchedName.empty() && f.virtualAddress > 0) {
            auto data = FksIndexManager::lookupByAddress(fksDir, meta.family, f.virtualAddress);
            matchedName = extractName(data);
            if (!matchedName.empty()) addrMatch++;
        }

        // Strategy 2: V2 short hash
        if (matchedName.empty() && f.hashesV2.shortHash != 0) {
            auto data = FksIndexManager::lookupByShortHashV2(fksDir, f.hashesV2.shortHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v2ShortMatch++;
        }

        // Strategy 3: V2 full hash
        if (matchedName.empty() && f.hashesV2.fullHash != 0 && f.hashesV2.fullHash != f.hashesV2.shortHash) {
            auto data = FksIndexManager::lookupByFullHashV2(fksDir, f.hashesV2.fullHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v2FullMatch++;
        }

        // Strategy 4: V2 mnemonic hash
        if (matchedName.empty() && f.hashesV2.mnemHash != 0) {
            auto data = FksIndexManager::lookupByMnemHashV2(fksDir, f.hashesV2.mnemHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v2MnemMatch++;
        }

        // Strategy 5: V2 call hash
        if (matchedName.empty() && f.hashesV2.callHash != 0) {
            auto data = FksIndexManager::lookupByCallHashV2(fksDir, f.hashesV2.callHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v2CallMatch++;
        }

        // Strategy 6: V1 full hash
        if (matchedName.empty() && f.hashes.fullHash != 0) {
            auto data = FksIndexManager::lookupByFullHash(fksDir, f.hashes.fullHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v1FullMatch++;
        }

        // Strategy 7: V1 short hash
        if (matchedName.empty() && f.hashes.shortHash != 0 && f.hashes.shortHash != f.hashes.fullHash) {
            auto data = FksIndexManager::lookupByShortHash(fksDir, f.hashes.shortHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v1ShortMatch++;
        }

        // Strategy 8: V1 call hash
        if (matchedName.empty() && f.hashes.callHash != 0) {
            auto data = FksIndexManager::lookupByCallHash(fksDir, f.hashes.callHash);
            matchedName = extractName(data);
            if (!matchedName.empty()) v1CallMatch++;
        }

        // Strategy 9: Body+instr composite
        if (matchedName.empty() && f.bodySize > 0 && f.instrCount > 0) {
            uint64_t composite = (static_cast<uint64_t>(f.bodySize) << 32) | f.instrCount;
            auto data = FksIndexManager::lookupByBodyInstr(fksDir, composite);
            matchedName = extractName(data);
            if (!matchedName.empty()) biMatch++;
        }

        // Strategy 10: Callee-set scoring (Step 10/11)
        if (matchedName.empty()) {
            // Get callees from relations
            std::vector<uint64_t> calleeUids;
            for (auto& rel : rels) {
                if (rel.callerIndex < funcs.size() && funcs[rel.callerIndex].uid == f.uid) {
                    if (rel.calleeIndex < funcs.size()) {
                        calleeUids.push_back(funcs[rel.calleeIndex].uid);
                    }
                }
            }

            if (!calleeUids.empty()) {
                // Try all hash types for multi-candidate lookup
                uint64_t hashes[] = { f.hashesV2.shortHash, f.hashesV2.fullHash,
                                      f.hashesV2.mnemHash, f.hashesV2.callHash,
                                      f.hashes.fullHash, f.hashes.shortHash, f.hashes.callHash };
                uint8_t prefixes[] = { 0x21, 0x20, 0x22, 0x23, 0x10, 0x11, 0x13 };

                for (int p = 0; p < 7; p++) {
                    if (hashes[p] == 0) continue;
                    auto data = FksIndexManager::lookupByHash(fksDir, prefixes[p], hashes[p]);
                    auto candidates = FksIndexManager::extractAllCandidates(data);
                    if (candidates.size() <= 1) continue;

                    // Multi-candidate: score by callee overlap
                    std::sort(calleeUids.begin(), calleeUids.end());

                    const CandidateInfo* best = nullptr;
                    int bestScore = -1;
                    for (auto& cand : candidates) {
                        int score = FksIndexManager::scoreCandidateByCallees(cand, calleeIndex, calleeUids);
                        if (score > bestScore) { bestScore = score; best = &cand; }
                    }
                    if (best && bestScore > 0) {
                        matchedName = best->name;
                        calleeMatch++;
                        break;
                    }
                }
            }
        }
    }

    int totalAutoGen = total - alreadyNamed;
    int totalIdentified = addrMatch + v2ShortMatch + v2FullMatch + v2MnemMatch + v2CallMatch
                        + v1FullMatch + v1ShortMatch + v1CallMatch + biMatch + calleeMatch;
    int unidentified = totalAutoGen - totalIdentified;

    // Report
    auto pct = [&](int n) -> double { return totalAutoGen > 0 ? 100.0 * n / totalAutoGen : 0; };

    std::cout << std::left << std::setw(35) << "Strategy"
              << std::right << std::setw(8) << "Count"
              << std::setw(10) << "Rate\n";
    std::cout << std::string(53, '-') << "\n";
    std::cout << std::left << std::setw(35) << "Pre-named (excluded)"
              << std::right << std::setw(8) << alreadyNamed << std::setw(9) << "-\n";
    std::cout << std::left << std::setw(35) << "Address-based"
              << std::right << std::setw(8) << addrMatch << std::setw(9) << std::fixed << std::setprecision(1) << pct(addrMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 short hash"
              << std::right << std::setw(8) << v2ShortMatch << std::setw(9) << pct(v2ShortMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 full hash"
              << std::right << std::setw(8) << v2FullMatch << std::setw(9) << pct(v2FullMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 mnemonic hash"
              << std::right << std::setw(8) << v2MnemMatch << std::setw(9) << pct(v2MnemMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 call hash"
              << std::right << std::setw(8) << v2CallMatch << std::setw(9) << pct(v2CallMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 full hash"
              << std::right << std::setw(8) << v1FullMatch << std::setw(9) << pct(v1FullMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 short hash"
              << std::right << std::setw(8) << v1ShortMatch << std::setw(9) << pct(v1ShortMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 call hash"
              << std::right << std::setw(8) << v1CallMatch << std::setw(9) << pct(v1CallMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "Body+instr composite"
              << std::right << std::setw(8) << biMatch << std::setw(9) << pct(biMatch) << "%\n";
    std::cout << std::left << std::setw(35) << "Callee-set scoring (Step 10/11)"
              << std::right << std::setw(8) << calleeMatch << std::setw(9) << pct(calleeMatch) << "%\n";
    std::cout << std::string(53, '-') << "\n";
    std::cout << std::left << std::setw(35) << "TOTAL IDENTIFIED"
              << std::right << std::setw(8) << totalIdentified << std::setw(9) << pct(totalIdentified) << "%\n";
    std::cout << std::left << std::setw(35) << "UNIDENTIFIED"
              << std::right << std::setw(8) << unidentified << std::setw(9) << pct(unidentified) << "%\n";

    return 0;
}
