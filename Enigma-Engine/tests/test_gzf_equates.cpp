/* ###
 * IP: Enigma Engine (original work)
 *
 * End-to-end test for GZF equate import + persistence:
 *
 *  1. Builds a synthetic Gbf container holding the two Ghidra equate tables
 *     ("Equates": long key = equate id, data [String name][Long value];
 *     "Equate References": long key = reference id, data [Long equate id]
 *     [Long address key][Short operand index][Long varnode hash]) exactly as
 *     Ghidra's EquateDBAdapterV0 / EquateRefDBAdapterV1 lay them out.
 *  2. Imports the fixture with GzfProgramImporter and asserts the equate
 *     table contents: names, values, and per-operand address bindings.
 *  3. Round-trips the program through a snapshot repository (commit + reload)
 *     and asserts the equate state (including bindings) is byte-identical.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/storage/CommitManager.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/storage/EventLog.h>
#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/EquateTable.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/import/GbfReader.h>
#include <ghidra/import/GzfProgramImporter.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace ghidra;
using namespace ghidra::storage;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace {

constexpr int kBlockSize = 512;
constexpr int kContentSize = kBlockSize - 5;  // 507

void putU32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off] = static_cast<uint8_t>(v >> 24);
    b[off + 1] = static_cast<uint8_t>(v >> 16);
    b[off + 2] = static_cast<uint8_t>(v >> 8);
    b[off + 3] = static_cast<uint8_t>(v);
}

void putU64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        b[off + static_cast<size_t>(i)] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

std::vector<uint8_t> strField(const std::string& s) {
    std::vector<uint8_t> out;
    uint32_t n = static_cast<uint32_t>(s.size());
    for (int i = 3; i >= 0; i--) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

std::vector<uint8_t> i32Field(int32_t v) {
    std::vector<uint8_t> out;
    for (int i = 3; i >= 0; i--) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    return out;
}

std::vector<uint8_t> i64Field(int64_t v) {
    std::vector<uint8_t> out;
    for (int i = 7; i >= 0; i--) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    return out;
}

std::vector<uint8_t> i8Field(int8_t v) {
    return {static_cast<uint8_t>(v)};
}

std::vector<uint8_t> binField(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> out = i32Field(static_cast<int32_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
}

// Address map key for the image space at the given 32-bit offset.
uint64_t imageKey(uint32_t offset) {
    return (0x20000000ull << 32) | offset;
}

/**
 * Synthetic Gbf database holding exactly the two equate tables:
 *   block 0  DBParms (parm0 = master root buffer id 1)
 *   block 1  master table leaf (long-key varrec) with 2 records
 *   block 2  Equates root leaf (type 1): keys 1..3 -> [String name][Long value]
 *   block 3  Equate References root leaf (type 2, fixed records):
 *            key = ref id; data [Long equate id][Long addr key][Short op index]
 *            [Long varnode hash]
 *
 * Reference records:
 *   ref 1: equate 1 @ image 0x1000 op 0          (applied)
 *   ref 2: equate 1 @ image 0x1004 op 1          (applied)
 *   ref 3: equate 3 @ image 0x1000 op 0          (applied)
 *   ref 4: equate 2 @ EXTERNAL space (0x50000000) -> skipped as bad
 */
std::vector<uint8_t> buildEquateFixture() {
    constexpr int kBlockCount = 4;
    std::vector<uint8_t> file(kBlockSize + kBlockCount * kBlockSize, 0);

    putU64(file, 0, GbfReader::kMagic);
    putU64(file, 8, 0xAABBCCDD00112233ULL);
    putU32(file, 16, 1);
    putU32(file, 20, kBlockSize);
    putU32(file, 24, kBlockCount + 1);
    putU32(file, 28, 0);

    std::vector<std::vector<uint8_t>> contents(kBlockCount,
        std::vector<uint8_t>(kContentSize, 0));

    // ---- block 0: DBParms: type(1)=9, dataLen(4)=9, version(1)=1, parm0=1
    contents[0][0] = 9;
    putU32(contents[0], 1, 9);
    contents[0][5] = 1;
    putU32(contents[0], 6, 1);

    // ---- master leaf (type 1): 2 records
    auto masterRecord = [](const std::string& name, int32_t ver, int32_t root,
                           int32_t keyType, const std::vector<uint8_t>& fieldTypes,
                           const std::string& fieldNames, int32_t recCount) {
        std::vector<uint8_t> r;
        std::vector<uint8_t> t = strField(name);
        r.insert(r.end(), t.begin(), t.end());
        t = i32Field(ver); r.insert(r.end(), t.begin(), t.end());
        t = i32Field(root); r.insert(r.end(), t.begin(), t.end());
        t = i8Field(static_cast<int8_t>(keyType)); r.insert(r.end(), t.begin(), t.end());
        t = binField(fieldTypes); r.insert(r.end(), t.begin(), t.end());
        t = strField(fieldNames); r.insert(r.end(), t.begin(), t.end());
        t = i32Field(-1); r.insert(r.end(), t.begin(), t.end());
        t = i64Field(100); r.insert(r.end(), t.begin(), t.end());
        t = i32Field(recCount); r.insert(r.end(), t.begin(), t.end());
        return r;
    };
    std::vector<std::vector<uint8_t>> masterRecs;
    masterRecs.push_back(masterRecord("Equates", 0, 2, 3, {4, 3},
                                      "Equate Name;Equate Value", 3));
    masterRecs.push_back(masterRecord("Equate References", 1, 3, 3,
                                      {3, 3, 1, 3},
                                      "Equate ID;Equate Reference;Operand Index;Varnode Hash",
                                      4));

    std::vector<uint8_t>& m = contents[1];
    m[0] = 1;
    putU32(m, 1, 2);
    size_t dataOff = kContentSize;
    for (int i = 1; i >= 0; i--) {
        std::vector<uint8_t>& r = masterRecs[static_cast<size_t>(i)];
        dataOff -= r.size();
        std::memcpy(&m[dataOff], r.data(), r.size());
        size_t e = 13 + static_cast<size_t>(i) * 13;
        putU64(m, e, static_cast<uint64_t>(i + 1));
        putU32(m, e + 8, static_cast<uint32_t>(dataOff));
        m[e + 12] = 0;
    }

    // ---- block 2: Equates leaf (type 1), keys 1..3
    std::vector<uint8_t>& e = contents[2];
    e[0] = 1;
    putU32(e, 1, 3);
    {
        // record i (key i+1): [String name][Long value]
        struct EqRec { std::string name; int64_t value; };
        const EqRec recs[] = {{"E_DOSCALL", 0x21}, {"E_STATUS", 0x100}, {"E_MASK", 0xFF}};
        size_t off = kContentSize;
        for (int i = 2; i >= 0; i--) {
            std::vector<uint8_t> rec = strField(recs[i].name);
            std::vector<uint8_t> v = i64Field(recs[i].value);
            rec.insert(rec.end(), v.begin(), v.end());
            off -= rec.size();
            std::memcpy(&e[off], rec.data(), rec.size());
            size_t ent = 13 + static_cast<size_t>(i) * 13;
            putU64(e, ent, static_cast<uint64_t>(i + 1));
            putU32(e, ent + 8, static_cast<uint32_t>(off));
            e[ent + 12] = 0;
        }
    }

    // ---- block 3: Equate References leaf (type 2, fixed rec size 26)
    std::vector<uint8_t>& r = contents[3];
    r[0] = 2;
    putU32(r, 1, 4);
    {
        struct RefRec { uint64_t equateId; uint64_t addrKey; uint16_t opIndex; uint64_t hash; };
        const RefRec recs[] = {
            {1, imageKey(0x1000), 0, 0x1234},
            {1, imageKey(0x1004), 1, 0},
            {3, imageKey(0x1000), 0, 0xDEAD},
            {2, (0x50000000ull << 32) | 0x20, 0, 0},  // external space: bad
        };
        constexpr size_t recSize = 8 + 8 + 2 + 8;  // 26
        constexpr size_t entrySize = 8 + recSize;  // 34
        for (int i = 0; i < 4; i++) {
            size_t ent = 13 + static_cast<size_t>(i) * entrySize;
            putU64(r, ent, static_cast<uint64_t>(i + 1));
            putU64(r, ent + 8, recs[i].equateId);
            putU64(r, ent + 16, recs[i].addrKey);
            r[ent + 24] = static_cast<uint8_t>(recs[i].opIndex >> 8);
            r[ent + 25] = static_cast<uint8_t>(recs[i].opIndex & 0xFF);
            putU64(r, ent + 26, recs[i].hash);
        }
    }

    // write slots: flags(1)=0, id(4), content
    for (int i = 0; i < kBlockCount; i++) {
        size_t base = static_cast<size_t>(i + 1) * kBlockSize;
        file[base] = 0;
        putU32(file, base + 1, static_cast<uint32_t>(i));
        std::memcpy(&file[base + 5], contents[static_cast<size_t>(i)].data(), kContentSize);
    }
    return file;
}

std::string makeTempRepo(const std::string& tag) {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::stringstream ss;
    ss << "repo_equates_" << tag << "_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    return path;
}

/** Canonical equate state: name/value per equate + one line per binding. */
std::string equateState(const ProgramDB& program) {
    std::ostringstream out;
    auto* et = program.getEquateTable();
    if (!et) return "";
    std::vector<std::string> lines;
    for (auto* eq : et->getEquates()) {
        if (!eq) continue;
        lines.push_back("Q|" + eq->getName() + "|" + std::to_string(eq->getValue()));
    }
    for (const auto& b : et->getAllBindings()) {
        if (!b.equate) continue;
        std::ostringstream line;
        line << "R|" << b.equate->getName() << "|" << b.addressOffset << "|" << b.opIndex;
        lines.push_back(line.str());
    }
    std::sort(lines.begin(), lines.end());
    for (const auto& l : lines) out << l << "\n";
    return out.str();
}

}  // namespace

int main() {
    // ================================================================
    // 1. Synthetic Gbf fixture import
    // ================================================================
    auto fixtureBytes = buildEquateFixture();
    auto reader = GbfReader::fromMemory(std::move(fixtureBytes));

    const GbfTableSchema* eqTable = reader->findTable("Equates");
    const GbfTableSchema* refTable = reader->findTable("Equate References");
    TEST("fixture: Equates table found", eqTable != nullptr);
    TEST("fixture: Equate References table found", refTable != nullptr);
    if (!eqTable || !refTable) return 1;

    GzfProgramImporter importer(*reader);
    std::unique_ptr<ProgramDB> program = importer.import("equate_fixture.exe");
    const auto& st = importer.getStats();
    for (const auto& w : importer.getWarnings()) {
        std::cout << "  warn: " << w << "\n";
    }

    TEST("fixture: equates imported", st.equates == 3);
    TEST("fixture: equate references applied", st.equateReferences == 3);
    TEST("fixture: bad references counted", st.equatesBad == 1);

    auto* et = program->getEquateTable();
    TEST("fixture: equate table present", et != nullptr);
    if (et) {
        TEST("fixture: equate count", et->getEquateCount() == 3);
        Equate* doscall = et->getEquate("E_DOSCALL");
        Equate* status = et->getEquate("E_STATUS");
        Equate* mask = et->getEquate("E_MASK");
        TEST("fixture: E_DOSCALL exists", doscall != nullptr);
        TEST("fixture: E_STATUS exists", status != nullptr);
        TEST("fixture: E_MASK exists", mask != nullptr);
        TEST("fixture: E_DOSCALL value", doscall && doscall->getValue() == 0x21);
        TEST("fixture: E_STATUS value", status && status->getValue() == 0x100);
        TEST("fixture: E_MASK value", mask && mask->getValue() == 0xFF);

        auto* space = const_cast<AddressSpace*>(
            program->getAddressFactory()->getDefaultAddressSpace());
        Address a1000(space, 0x1000);
        Address a1004(space, 0x1004);

        auto at1000op0 = et->getEquates(a1000, 0);
        auto at1004op1 = et->getEquates(a1004, 1);
        TEST("fixture: bindings at 0x1000 op 0",
             at1000op0.size() == 2 &&
                 (at1000op0[0]->getName() == "E_DOSCALL" || at1000op0[1]->getName() == "E_DOSCALL") &&
                 (at1000op0[0]->getName() == "E_MASK" || at1000op0[1]->getName() == "E_MASK"));
        TEST("fixture: binding at 0x1004 op 1",
             at1004op1.size() == 1 && at1004op1[0]->getName() == "E_DOSCALL");
        TEST("fixture: no binding at 0x1000 op 1", et->getEquates(a1000, 1).empty());
    }

    // ================================================================
    // 2. Snapshot round-trip (commit + reload)
    // ================================================================
    std::string stateA = equateState(*program);
    TEST("fixture: state dump non-empty", !stateA.empty());
    std::cout << "  equate state:\n" << stateA;

    std::string repoPath = makeTempRepo("eq");
    Repository::create(repoPath, "fidelity", "equate_fixture.exe", "0000",
                       program->getLanguageID().toString(),
                       program->getCompilerSpecID().toString(),
                       static_cast<uint64_t>(program->getImageBase().getOffset()));
    EventLog log;
    std::string cid = CommitManager::createCommit(repoPath, "", "original",
                                                  "fidelity", "main", *program, log);
    TEST("fixture: commit created", !cid.empty());

    auto r1 = SnapshotReader::loadFromFile(
        Repository::getCommitSnapshotPath(repoPath, cid));
    TEST("fixture: reload succeeds", r1 != nullptr);
    TEST("fixture: reload state identical", r1 && equateState(*r1) == stateA);
    if (r1 && equateState(*r1) != stateA) {
        std::cout << "  reloaded state:\n" << equateState(*r1);
    }
    fs::remove_all(repoPath);

    std::cout << "\n=== Gzf Equate Fidelity Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}