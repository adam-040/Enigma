// evaluate Identification rate against real Ghidra exports.
// Reads a JSON export, matches each function against LMDB, reports per-strategy ID rates.

#include <ghidra/storage/FksIndexManager.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

using json = nlohmann::json;
using namespace ghidra::storage;

static uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

struct FuncProfile {
    uint64_t address;
    std::string name;
    bool isNamed;
    uint64_t fullHashV1;
    uint64_t shortHashV1;
    uint64_t callHashV1;
    uint64_t fullHashV2;
    uint64_t shortHashV2;
    uint64_t mnemHashV2;
    uint64_t callHashV2;
    uint32_t bodySize;
    uint16_t instrCount;
    std::vector<uint64_t> callees;
};

std::string extractName(const std::vector<uint8_t>& data) {
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
        std::cerr << "Usage: " << argv[0] << " <fksDir> <export.json> <family>\n";
        return 1;
    }
    std::string fksDir = argv[1];
    std::string jsonPath = argv[2];
    std::string family = argv[3];

    // Load JSON export
    std::ifstream ifs(jsonPath);
    if (!ifs.is_open()) { std::cerr << "Cannot open " << jsonPath << "\n"; return 1; }
    json j;
    ifs >> j;

    // Parse function profiles
    std::vector<FuncProfile> funcs;
    for (auto& fj : j["functions"]) {
        FuncProfile f;
        f.address    = fj.value("address", 0ULL);
        f.name       = fj.value("name", "");
        f.isNamed    = !f.name.empty() && f.name.find("FUN_") != 0 && f.name.find("sub_") != 0;
        f.fullHashV1 = fj.value("full_hash", 0ULL);
        f.shortHashV1= fj.value("short_hash", 0ULL);
        f.callHashV1 = fj.value("call_hash", 0ULL);
        f.fullHashV2 = fj.value("full_hash_v2", 0ULL);
        f.shortHashV2= fj.value("short_hash_v2", 0ULL);
        f.mnemHashV2 = fj.value("mnem_hash_v2", 0ULL);
        f.callHashV2 = fj.value("call_hash_v2", 0ULL);
        f.bodySize   = fj.value("body_size", 0U);
        f.instrCount = fj.value("instr_count", 0);
        if (fj.contains("callees") && fj["callees"].is_array()) {
            for (auto& c : fj["callees"]) f.callees.push_back(c.get<uint64_t>());
        }
        funcs.push_back(f);
    }

    std::cout << "=== Identification Rate Evaluation ===\n";
    std::cout << "Library: " << family << "\n";
    std::cout << "Functions: " << funcs.size() << "\n";
    std::cout << "Pre-named: " << std::count_if(funcs.begin(), funcs.end(),
        [](auto& f){ return f.isNamed; }) << "\n\n";

    // Build callee index
    auto calleeIndex = FksIndexManager::buildCalleeIndex(fksDir);

    // Matching simulation
    int total = funcs.size();
    int addrMatch = 0, v2ShortMatch = 0, v2FullMatch = 0, v2MnemMatch = 0, v2CallMatch = 0;
    int v1FullMatch = 0, v1ShortMatch = 0, v1CallMatch = 0;
    int biMatch = 0, calleeMatch = 0;
    int totalIdentified = 0;

    // Track which functions were identified (to avoid double-counting)
    std::vector<bool> identified(total, false);

    for (int i = 0; i < total; i++) {
        auto& f = funcs[i];
        if (f.isNamed) { identified[i] = true; continue; }

        std::string matchedName;

        // Strategy 1: Address-based lookup
        if (matchedName.empty() && f.address > 0) {
            auto data = FksIndexManager::lookupByAddress(fksDir, family, f.address);
            matchedName = extractName(data);
            if (!matchedName.empty()) { addrMatch++; identified[i] = true; }
        }

        // Strategy 2: V2 short hash
        if (matchedName.empty() && f.shortHashV2 != 0) {
            auto data = FksIndexManager::lookupByShortHashV2(fksDir, f.shortHashV2);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v2ShortMatch++; identified[i] = true; }
        }

        // Strategy 3: V2 full hash
        if (matchedName.empty() && f.fullHashV2 != 0 && f.fullHashV2 != f.shortHashV2) {
            auto data = FksIndexManager::lookupByFullHashV2(fksDir, f.fullHashV2);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v2FullMatch++; identified[i] = true; }
        }

        // Strategy 4: V2 mnem hash
        if (matchedName.empty() && f.mnemHashV2 != 0) {
            auto data = FksIndexManager::lookupByMnemHashV2(fksDir, f.mnemHashV2);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v2MnemMatch++; identified[i] = true; }
        }

        // Strategy 5: V2 call hash
        if (matchedName.empty() && f.callHashV2 != 0) {
            auto data = FksIndexManager::lookupByCallHashV2(fksDir, f.callHashV2);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v2CallMatch++; identified[i] = true; }
        }

        // Strategy 6: V1 full hash
        if (matchedName.empty() && f.fullHashV1 != 0) {
            auto data = FksIndexManager::lookupByFullHash(fksDir, f.fullHashV1);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v1FullMatch++; identified[i] = true; }
        }

        // Strategy 7: V1 short hash
        if (matchedName.empty() && f.shortHashV1 != 0 && f.shortHashV1 != f.fullHashV1) {
            auto data = FksIndexManager::lookupByShortHash(fksDir, f.shortHashV1);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v1ShortMatch++; identified[i] = true; }
        }

        // Strategy 8: V1 call hash
        if (matchedName.empty() && f.callHashV1 != 0) {
            auto data = FksIndexManager::lookupByCallHash(fksDir, f.callHashV1);
            matchedName = extractName(data);
            if (!matchedName.empty()) { v1CallMatch++; identified[i] = true; }
        }

        // Strategy 9: Body+instr composite (Step 10 fallback)
        if (matchedName.empty() && f.bodySize > 0 && f.instrCount > 0) {
            uint64_t composite = (static_cast<uint64_t>(f.bodySize) << 32) | f.instrCount;
            auto data = FksIndexManager::lookupByBodyInstr(fksDir, composite);
            matchedName = extractName(data);
            if (!matchedName.empty()) { biMatch++; identified[i] = true; }
        }

        // Strategy 10: Callee-set matching (Step 10/11)
        if (matchedName.empty() && !f.callees.empty()) {
            // Score against all candidates from the best hash
            uint64_t bestHash = f.shortHashV2 ? f.shortHashV2 : f.fullHashV2;
            if (bestHash == 0) bestHash = f.fullHashV1;
            if (bestHash != 0) {
                auto data = FksIndexManager::lookupByShortHashV2(fksDir, bestHash);
                if (data.empty()) data = FksIndexManager::lookupByFullHashV2(fksDir, bestHash);
                if (data.empty()) data = FksIndexManager::lookupByFullHash(fksDir, bestHash);
                auto candidates = FksIndexManager::extractAllCandidates(data);
                if (candidates.size() > 1) {
                    // Multi-candidate: score by callee overlap
                    // Map local callees to UIDs using address lookup
                    std::vector<uint64_t> localCalleeUids;
                    for (uint64_t calleeAddr : f.callees) {
                        auto cdata = FksIndexManager::lookupByAddress(fksDir, family, calleeAddr);
                        auto cands = FksIndexManager::extractAllCandidates(cdata);
                        if (!cands.empty()) localCalleeUids.push_back(cands[0].uid);
                    }
                    std::sort(localCalleeUids.begin(), localCalleeUids.end());

                    const CandidateInfo* best = nullptr;
                    int bestScore = -1;
                    for (auto& cand : candidates) {
                        int score = FksIndexManager::scoreCandidateByCallees(cand, calleeIndex, localCalleeUids);
                        if (score > bestScore) { bestScore = score; best = &cand; }
                    }
                    if (best && bestScore >= 0) {
                        matchedName = best->name;
                        calleeMatch++;
                        identified[i] = true;
                    }
                }
            }
        }

        if (!matchedName.empty() && !identified[i]) {
            identified[i] = true;
        }
    }

    totalIdentified = std::count(identified.begin(), identified.end(), true);

    // Report
    int unidentified = total - totalIdentified;
    std::cout << "=== Results ===\n";
    std::cout << std::left << std::setw(35) << "Strategy" << std::right << std::setw(8) << "Count" << std::setw(10) << "Rate\n";
    std::cout << std::string(53, '-') << "\n";
    std::cout << std::left << std::setw(35) << "Pre-named"
              << std::right << std::setw(8) << std::count_if(funcs.begin(), funcs.end(), [](auto& f){return f.isNamed;})
              << std::setw(9) << std::fixed << std::setprecision(1)
              << (100.0 * std::count_if(funcs.begin(), funcs.end(), [](auto& f){return f.isNamed;}) / total) << "%\n";
    std::cout << std::left << std::setw(35) << "Address-based"
              << std::right << std::setw(8) << addrMatch
              << std::setw(9) << (100.0 * addrMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 short hash"
              << std::right << std::setw(8) << v2ShortMatch
              << std::setw(9) << (100.0 * v2ShortMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 full hash"
              << std::right << std::setw(8) << v2FullMatch
              << std::setw(9) << (100.0 * v2FullMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 mnemonic hash"
              << std::right << std::setw(8) << v2MnemMatch
              << std::setw(9) << (100.0 * v2MnemMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V2 call hash"
              << std::right << std::setw(8) << v2CallMatch
              << std::setw(9) << (100.0 * v2CallMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 full hash"
              << std::right << std::setw(8) << v1FullMatch
              << std::setw(9) << (100.0 * v1FullMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 short hash"
              << std::right << std::setw(8) << v1ShortMatch
              << std::setw(9) << (100.0 * v1ShortMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "V1 call hash"
              << std::right << std::setw(8) << v1CallMatch
              << std::setw(9) << (100.0 * v1CallMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "Body+instr composite"
              << std::right << std::setw(8) << biMatch
              << std::setw(9) << (100.0 * biMatch / total) << "%\n";
    std::cout << std::left << std::setw(35) << "Callee-set (Step 10/11)"
              << std::right << std::setw(8) << calleeMatch
              << std::setw(9) << (100.0 * calleeMatch / total) << "%\n";
    std::cout << std::string(53, '-') << "\n";
    std::cout << std::left << std::setw(35) << "TOTAL IDENTIFIED"
              << std::right << std::setw(8) << totalIdentified
              << std::setw(9) << (100.0 * totalIdentified / total) << "%\n";
    std::cout << std::left << std::setw(35) << "UNIDENTIFIED"
              << std::right << std::setw(8) << unidentified
              << std::setw(9) << (100.0 * unidentified / total) << "%\n";

    return 0;
}
