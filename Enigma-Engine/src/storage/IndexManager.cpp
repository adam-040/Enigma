#include <ghidra/storage/IndexManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <lmdb.h>
#include <vector>
#include <cstring>
#include <algorithm>

namespace ghidra {
namespace storage {

namespace {

// Key prefixes for LMDB database
constexpr uint8_t PREFIX_SYM_NAME_TO_ADDR = 0x00;
constexpr uint8_t PREFIX_SYM_ADDR_TO_NAME = 0x01;
constexpr uint8_t PREFIX_FUNC_NAME_TO_ADDR = 0x02;
constexpr uint8_t PREFIX_FUNC_ADDR_TO_NAME = 0x03;

static void putU64LE(uint8_t* buf, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        buf[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
}

static uint64_t getU64LE(const uint8_t* buf) {
    uint64_t val = 0;
    for (int i = 7; i >= 0; i--) {
        val <<= 8;
        val |= buf[i];
    }
    return val;
}

static std::vector<uint8_t> makeNameKey(uint8_t prefix, const std::string& name) {
    std::vector<uint8_t> key(1 + name.size());
    key[0] = prefix;
    std::copy(name.begin(), name.end(), key.begin() + 1);
    return key;
}

static std::vector<uint8_t> makeAddrKey(uint8_t prefix, uint64_t addr) {
    std::vector<uint8_t> key(1 + 8);
    key[0] = prefix;
    putU64LE(key.data() + 1, addr);
    return key;
}

static bool openEnv(const std::string& repoPath, MDB_env** env) {
    std::string lmdbDir = Repository::getIndexDir(repoPath);
    int rc = mdb_env_create(env);
    if (rc != 0) return false;
    rc = mdb_env_set_maxdbs(*env, 1);
    if (rc != 0) { mdb_env_close(*env); return false; }
    rc = mdb_env_open(*env, lmdbDir.c_str(), 0, 0664);
    if (rc != 0) { mdb_env_close(*env); return false; }
    return true;
}

static bool putEntry(MDB_txn* txn, MDB_dbi dbi,
                      const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& value) {
    MDB_val k{key.size(), const_cast<uint8_t*>(key.data())};
    MDB_val v{value.size(), const_cast<uint8_t*>(value.data())};
    int rc = mdb_put(txn, dbi, &k, &v, 0);
    return rc == 0;
}

static bool delEntry(MDB_txn* txn, MDB_dbi dbi, const std::vector<uint8_t>& key) {
    MDB_val k{key.size(), const_cast<uint8_t*>(key.data())};
    int rc = mdb_del(txn, dbi, &k, nullptr);
    return rc == 0;
}

static bool getEntry(MDB_txn* txn, MDB_dbi dbi,
                      const std::vector<uint8_t>& key,
                      std::vector<uint8_t>& value) {
    MDB_val k{key.size(), const_cast<uint8_t*>(key.data())};
    MDB_val v{0, nullptr};
    int rc = mdb_get(txn, dbi, &k, &v);
    if (rc != 0) return false;
    value.resize(v.mv_size);
    std::copy_n(static_cast<const uint8_t*>(v.mv_data), v.mv_size, value.data());
    return true;
}

} // anonymous namespace

bool IndexManager::rebuildFromProgramDB(const std::string& repoPath, const ProgramDB& program) {
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    // Index symbols
    if (auto* st = program.getSymbolTable()) {
        auto it = st->getAllProgramSymbols(true);
        while (it.hasNext()) {
            Symbol* sym = it.next();
            uint64_t addr = static_cast<uint64_t>(sym->getAddress().getOffset());
            std::string name = sym->getName();
            if (name.empty()) continue;

            auto addrBuf = std::vector<uint8_t>(8);
            putU64LE(addrBuf.data(), addr);

            // name → addr
            auto nameKey = makeNameKey(PREFIX_SYM_NAME_TO_ADDR, name);
            if (!putEntry(txn, dbi, nameKey, addrBuf)) continue;

            // addr → name
            auto addrKey = makeAddrKey(PREFIX_SYM_ADDR_TO_NAME, addr);
            auto nameBytes = std::vector<uint8_t>(name.begin(), name.end());
            putEntry(txn, dbi, addrKey, nameBytes);
        }
    }

    // Index functions
    if (auto* fm = program.getFunctionManager()) {
        auto it = fm->getFunctions(true);
        while (it.hasNext()) {
            Function* func = it.next();
            uint64_t entry = static_cast<uint64_t>(func->getEntryPoint().getOffset());
            std::string name = func->getName();
            if (name.empty()) continue;

            auto addrBuf = std::vector<uint8_t>(8);
            putU64LE(addrBuf.data(), entry);

            // name → entry
            auto nameKey = makeNameKey(PREFIX_FUNC_NAME_TO_ADDR, name);
            if (!putEntry(txn, dbi, nameKey, addrBuf)) continue;

            // entry → name
            auto entryKey = makeAddrKey(PREFIX_FUNC_ADDR_TO_NAME, entry);
            auto nameBytes = std::vector<uint8_t>(name.begin(), name.end());
            putEntry(txn, dbi, entryKey, nameBytes);
        }
    }

    rc = mdb_txn_commit(txn);
    mdb_env_close(env);
    return rc == 0;
}

bool IndexManager::addSymbol(const std::string& repoPath,
                              const std::string& name, uint64_t address) {
    if (name.empty()) return false;
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    auto addrBuf = std::vector<uint8_t>(8);
    putU64LE(addrBuf.data(), address);

    auto nameBytes = std::vector<uint8_t>(name.begin(), name.end());

    bool ok = true;
    ok = ok && putEntry(txn, dbi, makeNameKey(PREFIX_SYM_NAME_TO_ADDR, name), addrBuf);
    ok = ok && putEntry(txn, dbi, makeAddrKey(PREFIX_SYM_ADDR_TO_NAME, address), nameBytes);

    rc = ok ? mdb_txn_commit(txn) : (mdb_txn_abort(txn), -1);
    mdb_env_close(env);
    return rc == 0;
}

bool IndexManager::removeSymbol(const std::string& repoPath, const std::string& name) {
    if (name.empty()) return false;

    // Need to know the address to remove the reverse mapping
    uint64_t addr = lookupSymbol(repoPath, name);
    if (addr == 0) return false;

    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    bool ok = true;
    ok = ok && delEntry(txn, dbi, makeNameKey(PREFIX_SYM_NAME_TO_ADDR, name));
    ok = ok && delEntry(txn, dbi, makeAddrKey(PREFIX_SYM_ADDR_TO_NAME, addr));

    rc = ok ? mdb_txn_commit(txn) : (mdb_txn_abort(txn), -1);
    mdb_env_close(env);
    return rc == 0;
}

uint64_t IndexManager::lookupSymbol(const std::string& repoPath, const std::string& name) {
    if (name.empty()) return 0;
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return 0;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) { mdb_env_close(env); return 0; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, 0, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return 0; }

    std::vector<uint8_t> value;
    bool found = getEntry(txn, dbi, makeNameKey(PREFIX_SYM_NAME_TO_ADDR, name), value);

    mdb_txn_abort(txn);
    mdb_env_close(env);

    if (!found || value.size() != 8) return 0;
    return getU64LE(value.data());
}

std::string IndexManager::lookupSymbolByAddress(const std::string& repoPath, uint64_t address) {
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return "";

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) { mdb_env_close(env); return ""; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, 0, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return ""; }

    std::vector<uint8_t> value;
    bool found = getEntry(txn, dbi, makeAddrKey(PREFIX_SYM_ADDR_TO_NAME, address), value);

    mdb_txn_abort(txn);
    mdb_env_close(env);

    if (!found) return "";
    return std::string(value.begin(), value.end());
}

bool IndexManager::addFunction(const std::string& repoPath,
                                const std::string& name, uint64_t entryPoint) {
    if (name.empty()) return false;
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    auto addrBuf = std::vector<uint8_t>(8);
    putU64LE(addrBuf.data(), entryPoint);

    auto nameBytes = std::vector<uint8_t>(name.begin(), name.end());

    bool ok = true;
    ok = ok && putEntry(txn, dbi, makeNameKey(PREFIX_FUNC_NAME_TO_ADDR, name), addrBuf);
    ok = ok && putEntry(txn, dbi, makeAddrKey(PREFIX_FUNC_ADDR_TO_NAME, entryPoint), nameBytes);

    rc = ok ? mdb_txn_commit(txn) : (mdb_txn_abort(txn), -1);
    mdb_env_close(env);
    return rc == 0;
}

bool IndexManager::removeFunction(const std::string& repoPath, const std::string& name) {
    if (name.empty()) return false;

    uint64_t entry = lookupFunction(repoPath, name);
    if (entry == 0) return false;

    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); return false; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return false; }

    bool ok = true;
    ok = ok && delEntry(txn, dbi, makeNameKey(PREFIX_FUNC_NAME_TO_ADDR, name));
    ok = ok && delEntry(txn, dbi, makeAddrKey(PREFIX_FUNC_ADDR_TO_NAME, entry));

    rc = ok ? mdb_txn_commit(txn) : (mdb_txn_abort(txn), -1);
    mdb_env_close(env);
    return rc == 0;
}

uint64_t IndexManager::lookupFunction(const std::string& repoPath, const std::string& name) {
    if (name.empty()) return 0;
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return 0;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) { mdb_env_close(env); return 0; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, 0, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return 0; }

    std::vector<uint8_t> value;
    bool found = getEntry(txn, dbi, makeNameKey(PREFIX_FUNC_NAME_TO_ADDR, name), value);

    mdb_txn_abort(txn);
    mdb_env_close(env);

    if (!found || value.size() != 8) return 0;
    return getU64LE(value.data());
}

std::string IndexManager::lookupFunctionByEntry(const std::string& repoPath, uint64_t entryPoint) {
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return "";

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) { mdb_env_close(env); return ""; }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, nullptr, 0, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); return ""; }

    std::vector<uint8_t> value;
    bool found = getEntry(txn, dbi, makeAddrKey(PREFIX_FUNC_ADDR_TO_NAME, entryPoint), value);

    mdb_txn_abort(txn);
    mdb_env_close(env);

    if (!found) return "";
    return std::string(value.begin(), value.end());
}

bool IndexManager::clear(const std::string& repoPath) {
    MDB_env* env = nullptr;
    if (!openEnv(repoPath, &env)) return false;

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

} // namespace storage
} // namespace ghidra
