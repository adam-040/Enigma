/* ###
 * IP: GHIDRA
 *
 * FksIndexManager — LMDB index for FKS hash lookups.
 * Mirrors the IndexManager pattern with key prefixes 0x10–0x13.
 */
#include <ghidra/storage/FksIndexManager.h>
#include <ghidra/storage/FksRepository.h>
#include <ghidra/FksLibrary.h>
#include <fks_generated.h>
#include <flatbuffers/flatbuffers.h>
#include <lmdb.h>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <filesystem>
#include <unordered_set>
#include <algorithm>

namespace ghidra {
namespace storage {

namespace fs = std::filesystem;

namespace {

// ── LE uint64 helpers (same as IndexManager) ─────────────────────────────────

void putU64LE(uint8_t* buf, uint64_t val) {
    for (int i = 0; i < 8; i++) { buf[i] = static_cast<uint8_t>(val & 0xFF); val >>= 8; }
}

// ── Key builders ─────────────────────────────────────────────────────────────

std::vector<uint8_t> makeHashKey(uint8_t prefix, uint64_t hash) {
    std::vector<uint8_t> key(1 + 8);
    key[0] = prefix;
    putU64LE(key.data() + 1, hash);
    return key;
}

uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

std::vector<uint8_t> makeAddressKey(uint8_t prefix, const std::string& family, uint64_t address) {
    std::vector<uint8_t> key(1 + 8 + 8);
    key[0] = prefix;
    putU64LE(key.data() + 1, fnv1a64(family));
    putU64LE(key.data() + 9, address);
    return key;
}

std::vector<uint8_t> makeCompositeKey(uint8_t prefix, uint32_t a, uint32_t b) {
    std::vector<uint8_t> key(1 + 4 + 4);
    key[0] = prefix;
    putU64LE(key.data() + 1, (static_cast<uint64_t>(a) << 32) | b);
    return key;
}

// ── LMDB lifecycle ───────────────────────────────────────────────────────────

bool openFksEnv(const std::string& fksDir, MDB_env** env) {
    std::string lmdbDir = FksRepository::getIndexDir(fksDir);
    std::error_code ec;
    fs::create_directories(lmdbDir, ec);
    int rc = mdb_env_create(env);
    if (rc != 0) return false;
    rc = mdb_env_set_mapsize(*env, 1024UL * 1024 * 1024);
    if (rc != 0) { mdb_env_close(*env); return false; }
    rc = mdb_env_set_maxdbs(*env, 1);
    if (rc != 0) { mdb_env_close(*env); return false; }
    rc = mdb_env_open(*env, lmdbDir.c_str(), 0, 0664);
    if (rc != 0) { mdb_env_close(*env); return false; }
    return true;
}

bool putEntry(MDB_txn* txn, MDB_dbi dbi,
              const std::vector<uint8_t>& key,
              const std::vector<uint8_t>& value) {
    MDB_val k{key.size(), const_cast<uint8_t*>(key.data())};
    MDB_val v{value.size(), const_cast<uint8_t*>(value.data())};
    return mdb_put(txn, dbi, &k, &v, 0) == 0;
}

bool getEntry(MDB_txn* txn, MDB_dbi dbi,
              const std::vector<uint8_t>& key,
              std::vector<uint8_t>& value) {
    MDB_val k{key.size(), const_cast<uint8_t*>(key.data())};
    MDB_val v{0, nullptr};
    if (mdb_get(txn, dbi, &k, &v) != 0) return false;
    value.resize(v.mv_size);
    std::copy_n(static_cast<const uint8_t*>(v.mv_data), v.mv_size, value.data());
    return true;
}

// ── FlatBuffer helpers for FkCandidateList ───────────────────────────────────

namespace fb = fbschema;

// Key for the unordered_map: prefix + hash
struct HashKey {
    uint8_t  prefix;
    uint64_t hash;
    bool operator==(const HashKey& o) const { return prefix == o.prefix && hash == o.hash; }
};

struct HashKeyHash {
    size_t operator()(const HashKey& k) const {
        return std::hash<uint8_t>()(k.prefix) ^ (std::hash<uint64_t>()(k.hash) << 1);
    }
};

struct CandidateEntry {
    uint64_t uid;
    std::string name;
    std::string nameDemangled;
    std::string namespacePath;
    std::string signature;
    std::string family;
    std::string compiler;
    uint32_t bodySize;
    uint16_t instrCount;
};

std::vector<uint8_t> serializeCandidateList(
    const std::string& family,
    const std::string& compiler,
    const std::vector<CandidateEntry>& candidates)
{
    flatbuffers::FlatBufferBuilder builder(1024);

    std::vector<flatbuffers::Offset<fb::FkCandidate>> fbCandidates;
    fbCandidates.reserve(candidates.size());
    for (auto& c : candidates) {
        auto nameStr    = builder.CreateString(c.name);
        auto demStr     = builder.CreateString(c.nameDemangled);
        auto nsStr      = builder.CreateString(c.namespacePath);
        auto sigStr     = builder.CreateString(c.signature);
        auto familyStr  = builder.CreateString(family);
        auto compilerStr = builder.CreateString(compiler);
        fbCandidates.push_back(fb::CreateFkCandidate(
            builder, c.uid, nameStr, demStr, nsStr, familyStr, compilerStr,
            c.bodySize, c.instrCount, sigStr));
    }
    auto vec = builder.CreateVector(fbCandidates);
    auto root = fb::CreateFkCandidateList(builder, vec);
    builder.Finish(root);

    auto* buf = builder.GetBufferPointer();
    auto size = builder.GetSize();
    return std::vector<uint8_t>(buf, buf + size);
}

// Write with collision merge: if key exists, merge candidates instead of overwriting.
bool putEntryMerge(MDB_txn* txn, MDB_dbi dbi,
                   const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& newValue) {
    MDB_val k{key.size(), const_cast<uint8_t*>(key.data())};
    MDB_val v{newValue.size(), const_cast<uint8_t*>(newValue.data())};

    int rc = mdb_put(txn, dbi, &k, &v, MDB_NOOVERWRITE);
    if (rc == 0) return true;
    if (rc != MDB_KEYEXIST) return false;

    MDB_val existing{0, nullptr};
    rc = mdb_get(txn, dbi, &k, &existing);
    if (rc != 0) return false;
    if (existing.mv_size == 0) return false;

    auto existingCandidates = FksIndexManager::extractAllCandidates(
        std::vector<uint8_t>(
            static_cast<const uint8_t*>(existing.mv_data),
            static_cast<const uint8_t*>(existing.mv_data) + existing.mv_size));

    auto newCandidates = FksIndexManager::extractAllCandidates(newValue);

    std::unordered_set<uint64_t> existingUids;
    for (auto& c : existingCandidates) existingUids.insert(c.uid);

    std::vector<CandidateEntry> merged;
    auto addEntry = [&](const std::string& family, const std::string& compiler,
                        const CandidateInfo& c) {
        CandidateEntry e;
        e.uid = c.uid; e.name = c.name; e.nameDemangled = c.nameDemangled;
        e.namespacePath = c.namespacePath; e.signature = c.signature;
        e.family = family; e.compiler = compiler;
        e.bodySize = c.bodySize; e.instrCount = c.instrCount;
        merged.push_back(std::move(e));
    };

    std::string mergeFamily = newCandidates.empty() ? "unknown" : newCandidates[0].family;
    std::string mergeCompiler = newCandidates.empty() ? "unknown" : newCandidates[0].compiler;

    for (auto& c : existingCandidates) addEntry(mergeFamily, mergeCompiler, c);
    for (auto& c : newCandidates) {
        if (existingUids.count(c.uid)) continue;
        addEntry(mergeFamily, mergeCompiler, c);
    }

    auto serialized = serializeCandidateList(mergeFamily, mergeCompiler, merged);
    v.mv_data = const_cast<uint8_t*>(serialized.data());
    v.mv_size = serialized.size();
    rc = mdb_put(txn, dbi, &k, &v, 0);
    return rc == 0;
}

} // anonymous namespace

// ── Public API ───────────────────────────────────────────────────────────────

bool FksIndexManager::indexExists(const std::string& fksDir) {
    std::string mdbPath = FksRepository::getIndexDir(fksDir) + "/data.mdb";
    return fs::exists(mdbPath);
}

bool FksIndexManager::clear(const std::string& fksDir) {
    MDB_env* env = nullptr;
    if (!openFksEnv(fksDir, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    rc = mdb_drop(txn, dbi, 0);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    rc = mdb_txn_commit(txn);
    mdb_env_close(env);
    return rc == 0;
}

bool FksIndexManager::indexLibrary(const std::string& fksDir, const FksLibrary& lib) {
    MDB_env* env = nullptr;
    if (!openFksEnv(fksDir, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    // Two-pass: collect candidates per hash key, then serialize and store.
    std::unordered_map<HashKey, std::vector<CandidateEntry>, HashKeyHash> groups;

    uint8_t prefixes[] = {PREFIX_FULL_HASH, PREFIX_SHORT_HASH,
                          PREFIX_FULL_HASH_V2, PREFIX_SHORT_HASH_V2, PREFIX_MNEM_HASH_V2, PREFIX_CALL_HASH_V2};

    for (auto& func : lib.getFunctions()) {
        uint64_t hashes[] = {func.hashes.fullHash, func.hashes.shortHash,
                             func.hashesV2.fullHash, func.hashesV2.shortHash,
                             func.hashesV2.mnemHash, func.hashesV2.callHash};

        CandidateEntry entry;
        entry.uid           = func.uid;
        entry.name          = func.name;
        entry.nameDemangled = func.nameDemangled;
        entry.namespacePath = func.namespacePath;
        entry.signature     = func.signature;
        entry.bodySize      = func.bodySize;
        entry.instrCount    = func.instrCount;
        for (int i = 0; i < 6; i++) {
            if (hashes[i] == 0) continue;
            groups[HashKey{prefixes[i], hashes[i]}].push_back(entry);
        }
    }

    bool ok = true;
    auto family   = lib.getMeta().family;
    auto compiler = lib.getMeta().compiler;

    for (auto& [key, candidates] : groups) {
        auto serialized = serializeCandidateList(family, compiler, candidates);
        std::vector<uint8_t> lmdbKey = makeHashKey(key.prefix, key.hash);
        ok = ok && putEntryMerge(txn, dbi, lmdbKey, serialized);
        if (!ok) break;
    }

    // Address-based indexing
    if (ok) {
        for (auto& func : lib.getFunctions()) {
            if (func.virtualAddress == 0) continue;
            CandidateEntry entry;
            entry.uid           = func.uid;
            entry.name          = func.name;
            entry.nameDemangled = func.nameDemangled;
            entry.namespacePath = func.namespacePath;
            entry.signature     = func.signature;
            entry.bodySize      = func.bodySize;
            entry.instrCount    = func.instrCount;
            auto serialized = serializeCandidateList(family, compiler, {entry});
            auto addrKey = makeAddressKey(PREFIX_ADDRESS, family, func.virtualAddress);
            ok = ok && putEntryMerge(txn, dbi, addrKey, serialized);
            if (!ok) break;
        }
    }

    // Body+Instr composite key indexing (0x50)
    if (ok) {
        std::unordered_map<uint64_t, std::vector<CandidateEntry>> biGroups;
        for (auto& func : lib.getFunctions()) {
            uint64_t composite = (static_cast<uint64_t>(func.bodySize) << 32) | func.instrCount;
            CandidateEntry entry;
            entry.uid           = func.uid;
            entry.name          = func.name;
            entry.nameDemangled = func.nameDemangled;
            entry.namespacePath = func.namespacePath;
            entry.signature     = func.signature;
            entry.bodySize      = func.bodySize;
            entry.instrCount    = func.instrCount;
            biGroups[composite].push_back(entry);
        }
        for (auto& [composite, candidates] : biGroups) {
            auto serialized = serializeCandidateList(family, compiler, candidates);
            auto key = makeHashKey(PREFIX_BODY_INSTR, composite);
            ok = ok && putEntryMerge(txn, dbi, key, serialized);
            if (!ok) break;
        }
    }

    rc = ok ? mdb_txn_commit(txn) : (mdb_txn_abort(txn), -1);
    mdb_env_close(env);
    return rc == 0;
}

int FksIndexManager::rebuildFromFksDir(const std::string& fksDir) {
    int totalFunctions = 0;

    for (auto& entry : fs::directory_iterator(fksDir)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".fkslib") continue;

        try {
            auto lib = FksLibrary::loadFromFile(entry.path().string());
            if (!lib) continue;
            indexLibrary(fksDir, *lib);
            totalFunctions += lib->functionCount();
        } catch (...) {
            continue;
        }
    }

    return totalFunctions;
}

std::vector<uint8_t> FksIndexManager::lookupByHash(const std::string& fksDir,
                                                    uint8_t prefix, uint64_t hash) {
    MDB_env* env = nullptr;
    if (!openFksEnv(fksDir, &env)) return {};

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) { mdb_env_close(env); return {}; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, 0, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return {}; }

    auto key = makeHashKey(prefix, hash);
    std::vector<uint8_t> value;
    bool found = getEntry(txn, dbi, key, value);

    mdb_txn_abort(txn);
    mdb_env_close(env);

    return found ? value : std::vector<uint8_t>{};
}

std::vector<uint8_t> FksIndexManager::lookupByFullHash(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_FULL_HASH, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByShortHash(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_SHORT_HASH, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByMnemHash(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_MNEM_HASH, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByCallHash(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_CALL_HASH, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByFullHashV2(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_FULL_HASH_V2, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByShortHashV2(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_SHORT_HASH_V2, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByMnemHashV2(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_MNEM_HASH_V2, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByCallHashV2(const std::string& fksDir, uint64_t hash) {
    return lookupByHash(fksDir, PREFIX_CALL_HASH_V2, hash);
}

std::vector<uint8_t> FksIndexManager::lookupByAddress(const std::string& fksDir,
                                                       const std::string& family, uint64_t address) {
    MDB_env* env = nullptr;
    if (!openFksEnv(fksDir, &env)) return {};

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) { mdb_env_close(env); return {}; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, 0, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return {}; }

    auto key = makeAddressKey(PREFIX_ADDRESS, family, address);
    std::vector<uint8_t> value;
    bool found = getEntry(txn, dbi, key, value);

    mdb_txn_abort(txn);
    mdb_env_close(env);

    return found ? value : std::vector<uint8_t>{};
}

std::vector<uint8_t> FksIndexManager::lookupByDemangledName(const std::string& fksDir, uint64_t nameHash) {
    return lookupByHash(fksDir, PREFIX_DEMANGLED_NAME, nameHash);
}

std::vector<uint8_t> FksIndexManager::lookupByNamespace(const std::string& fksDir, uint64_t nsHash) {
    return lookupByHash(fksDir, PREFIX_NAMESPACE, nsHash);
}

std::vector<uint8_t> FksIndexManager::lookupByBodyInstr(const std::string& fksDir, uint64_t compositeKey) {
    return lookupByHash(fksDir, PREFIX_BODY_INSTR, compositeKey);
}

std::vector<CandidateInfo> FksIndexManager::extractAllCandidates(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    auto verifier = flatbuffers::Verifier(data.data(), data.size());
    if (!verifier.VerifyBuffer<fbschema::FkCandidateList>()) return {};
    auto* list = flatbuffers::GetRoot<fbschema::FkCandidateList>(data.data());
    if (!list || !list->candidates()) return {};

    std::vector<CandidateInfo> result;
    result.reserve(list->candidates()->size());
    for (auto* c : *list->candidates()) {
        if (!c || !c->name()) continue;
        CandidateInfo info;
        info.uid            = c->uid();
        info.name           = c->name()->str();
        info.nameDemangled  = c->name_demangled() ? c->name_demangled()->str() : "";
        info.namespacePath  = c->namespace_path() ? c->namespace_path()->str() : "";
        info.signature      = c->signature() ? c->signature()->str() : "";
        info.family         = c->library_family() ? c->library_family()->str() : "";
        info.compiler       = c->library_compiler() ? c->library_compiler()->str() : "";
        info.bodySize       = c->body_size();
        info.instrCount     = c->instr_count();
        result.push_back(std::move(info));
    }
    return result;
}

std::unordered_map<uint64_t, std::vector<uint64_t>> FksIndexManager::buildCalleeIndex(
    const std::string& fksDir)
{
    // Static cache key: dir path + mtime hash of all .fkslib files.
    // Invalidates when any .fkslib is added, removed, or modified.
    static std::string cachedKey;
    static std::unordered_map<uint64_t, std::vector<uint64_t>> cachedIndex;
    static bool populated = false;

    std::string currentKey = fksDir;
    {
        uint64_t mtimeAccum = 0;
        for (auto& entry : fs::directory_iterator(fksDir)) {
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".fkslib") continue;
            auto ft = fs::last_write_time(entry.path());
            mtimeAccum ^= static_cast<uint64_t>(ft.time_since_epoch().count()) + 0x9e3779b9 + (mtimeAccum << 6) + (mtimeAccum >> 2);
        }
        currentKey += ":" + std::to_string(mtimeAccum);
    }

    if (populated && cachedKey == currentKey) {
        return cachedIndex;
    }

    cachedIndex.clear();
    cachedKey = currentKey;

    for (auto& entry : fs::directory_iterator(fksDir)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".fkslib") continue;

        try {
            auto lib = FksLibrary::loadFromFile(entry.path().string());
            if (!lib) continue;

            // Build local index: function index → UID
            auto& funcs = lib->getFunctions();
            std::vector<uint64_t> uidByIndex(funcs.size());
            for (size_t i = 0; i < funcs.size(); i++) {
                uidByIndex[i] = funcs[i].uid;
            }

            // Populate callee index from relations
            for (auto& rel : lib->getRelations()) {
                if (rel.callerIndex < funcs.size() && rel.calleeIndex < funcs.size()) {
                    uint64_t callerUid = uidByIndex[rel.callerIndex];
                    uint64_t calleeUid = uidByIndex[rel.calleeIndex];
                    cachedIndex[callerUid].push_back(calleeUid);
                }
            }

        } catch (...) {
            continue;
        }
    }

    // Sort callee vectors once for consistent comparison
    for (auto& [uid, callees] : cachedIndex) {
        std::sort(callees.begin(), callees.end());
    }

    populated = true;
    return cachedIndex;
}

int FksIndexManager::scoreCandidateByCallees(
    const CandidateInfo& candidate,
    const std::unordered_map<uint64_t, std::vector<uint64_t>>& calleeIndex,
    const std::vector<uint64_t>& localCallees)
{
    if (localCallees.empty()) return 0;

    auto it = calleeIndex.find(candidate.uid);
    if (it == calleeIndex.end()) return 0;

    const auto& candidateCallees = it->second;
    if (candidateCallees.empty()) return 0;

    // Count overlapping callee UIDs
    int overlap = 0;
    size_t i = 0, j = 0;
    while (i < localCallees.size() && j < candidateCallees.size()) {
        if (localCallees[i] == candidateCallees[j]) {
            ++overlap;
            ++i;
            ++j;
        } else if (localCallees[i] < candidateCallees[j]) {
            ++i;
        } else {
            ++j;
        }
    }

    return overlap;
}

} // namespace storage
} // namespace ghidra
