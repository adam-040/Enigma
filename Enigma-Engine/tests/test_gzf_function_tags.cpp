/* ###
 * IP: Enigma Engine (original work)
 *
 * End-to-end test for GZF function tag import + persistence:
 *
 *  1. Builds a synthetic Gbf container holding the two Ghidra function tag
 *     tables exactly as FunctionTagAdapterV0 / FunctionTagMappingAdapterV0
 *     lay them out ("Function Tags": long key = tag id, data [String tag]
 *     [String comment]; "Function Tag Map": long key = map id, data [Long
 *     function id][Long tag id]), plus the minimal Symbols/Function Data
 *     tables needed to materialize one function (the tag map's function id
 *     is the function symbol's id).
 *  2. Imports the fixture with GzfProgramImporter and asserts the tag table
 *     contents: tag names/comments and tag -> function assignments (one
 *     record references an unknown function id and must be counted as bad).
 *  3. Round-trips the program through a snapshot repository (commit + reload)
 *     and asserts the tag state is identical.
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
#include <ghidra/Function.h>
#include <ghidra/FunctionTagManager.h>
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
 * Synthetic Gbf database holding the two function tag tables plus the
 * minimal symbol/function tables:
 *   block 0  DBParms (parm0 = master root buffer id 1)
 *   block 1  master table leaf (long-key varrec) with 4 records
 *   block 2  Function Tags leaf (type 1): keys 1..2 ->
 *            [String tag][String comment]
 *   block 3  Function Tag Map leaf (type 2, fixed records, size 16):
 *            key = map id; data [Long function id][Long tag id]
 *   block 4  Symbols leaf (type 1): key 100 -> [String name][Long address]
 *            [Long namespace][Byte type][Byte flags]  (type 5 = function)
 *   block 5  Function Data leaf (type 1): key 100 -> [Long return dt id]
 *            [Int stack purge][Int stack return offset][Int stack local size]
 *            [Byte flags][Byte calling convention id][String return storage]
 *
 * Tag map records:
 *   rec 1: function 100 (F1) <- tag 1 (IMPORTANT)
 *   rec 2: function 100 (F1) <- tag 2 (ENTRY)
 *   rec 3: function 999 (unknown) <- tag 1  -> counted as bad
 */
std::vector<uint8_t> buildFunctionTagFixture() {
    constexpr int kBlockCount = 6;
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

    // ---- master leaf (type 1): 4 records
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
    masterRecs.push_back(masterRecord("Function Tags", 0, 2, 3, {4, 4},
                                      "Tag;Comment", 2));
    masterRecs.push_back(masterRecord("Function Tag Map", 0, 3, 3, {3, 3},
                                      "Function ID;Tag ID", 3));
    masterRecs.push_back(masterRecord("Symbols", 4, 4, 3, {4, 3, 3, 0, 0},
                                      "Name;Address;Namespace;Symbol Type;Flags", 1));
    masterRecs.push_back(masterRecord("Function Data", 0, 5, 3,
                                      {3, 2, 2, 2, 0, 0, 4},
                                      "Return Datatype ID;Stack Purge;"
                                      "Stack Return Offset;Stack Local Size;"
                                      "Flags;Calling Convention ID;Return Storage", 1));

    std::vector<uint8_t>& m = contents[1];
    m[0] = 1;
    putU32(m, 1, 4);
    size_t dataOff = kContentSize;
    for (int i = 3; i >= 0; i--) {
        std::vector<uint8_t>& r = masterRecs[static_cast<size_t>(i)];
        dataOff -= r.size();
        std::memcpy(&m[dataOff], r.data(), r.size());
        size_t e = 13 + static_cast<size_t>(i) * 13;
        putU64(m, e, static_cast<uint64_t>(i + 1));
        putU32(m, e + 8, static_cast<uint32_t>(dataOff));
        m[e + 12] = 0;
    }

    // ---- block 2: Function Tags leaf (type 1), keys 1..2
    std::vector<uint8_t>& t = contents[2];
    t[0] = 1;
    putU32(t, 1, 2);
    {
        // record i (key i+1): [String tag][String comment]
        struct TagRec { std::string name; std::string comment; };
        const TagRec recs[] = {{"IMPORTANT", "vital code"}, {"ENTRY", ""}};
        size_t off = kContentSize;
        for (int i = 1; i >= 0; i--) {
            std::vector<uint8_t> rec = strField(recs[i].name);
            std::vector<uint8_t> c = strField(recs[i].comment);
            rec.insert(rec.end(), c.begin(), c.end());
            off -= rec.size();
            std::memcpy(&t[off], rec.data(), rec.size());
            size_t ent = 13 + static_cast<size_t>(i) * 13;
            putU64(t, ent, static_cast<uint64_t>(i + 1));
            putU32(t, ent + 8, static_cast<uint32_t>(off));
            t[ent + 12] = 0;
        }
    }

    // ---- block 3: Function Tag Map leaf (type 2, fixed rec size 16)
    std::vector<uint8_t>& tm = contents[3];
    tm[0] = 2;
    putU32(tm, 1, 3);
    {
        struct MapRec { uint64_t funcId; uint64_t tagId; };
        const MapRec recs[] = {
            {100, 1},
            {100, 2},
            {999, 1},  // unknown function: bad
        };
        constexpr size_t recSize = 16;
        constexpr size_t entrySize = 8 + recSize;  // 24
        for (int i = 0; i < 3; i++) {
            size_t ent = 13 + static_cast<size_t>(i) * entrySize;
            putU64(tm, ent, static_cast<uint64_t>(i + 1));
            putU64(tm, ent + 8, recs[i].funcId);
            putU64(tm, ent + 16, recs[i].tagId);
        }
    }

    // ---- block 4: Symbols leaf (type 1), key 100 (function symbol id)
    std::vector<uint8_t>& s = contents[4];
    s[0] = 1;
    putU32(s, 1, 1);
    {
        // [String name][Long address][Long namespace][Byte type][Byte flags]
        std::vector<uint8_t> rec = strField("F1");
        std::vector<uint8_t> v = i64Field(static_cast<int64_t>(imageKey(0x1000)));
        rec.insert(rec.end(), v.begin(), v.end());
        v = i64Field(0);
        rec.insert(rec.end(), v.begin(), v.end());
        rec.push_back(5);  // SYMBOL_TYPE_FUNCTION
        rec.push_back(0);  // source type flags
        size_t off = kContentSize - rec.size();
        std::memcpy(&s[off], rec.data(), rec.size());
        putU64(s, 13, 100);
        putU32(s, 21, static_cast<uint32_t>(off));
        s[25] = 0;
    }

    // ---- block 5: Function Data leaf (type 1), key 100
    std::vector<uint8_t>& fd = contents[5];
    fd[0] = 1;
    putU32(fd, 1, 1);
    {
        // [Long return dt id][Int purge][Int return off][Int local size]
        // [Byte flags][Byte cc id][String return storage]
        std::vector<uint8_t> rec = i64Field(0);
        std::vector<uint8_t> v = i32Field(0);
        rec.insert(rec.end(), v.begin(), v.end());
        v = i32Field(0);
        rec.insert(rec.end(), v.begin(), v.end());
        v = i32Field(0);
        rec.insert(rec.end(), v.begin(), v.end());
        rec.push_back(0);
        rec.push_back(0);
        v = strField("");
        rec.insert(rec.end(), v.begin(), v.end());
        size_t off = kContentSize - rec.size();
        std::memcpy(&fd[off], rec.data(), rec.size());
        putU64(fd, 13, 100);
        putU32(fd, 21, static_cast<uint32_t>(off));
        fd[25] = 0;
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
    ss << "repo_tags_" << tag << "_" << std::hex << ms;
    std::string path = ss.str();
    fs::remove_all(path);
    return path;
}

/** Canonical tag state: one G line per tag + one GA line per assignment. */
std::string tagState(const ProgramDB& program) {
    std::ostringstream out;
    std::vector<std::string> lines;
    if (auto* ftm = program.getFunctionTagManager()) {
        for (auto* tag : ftm->getAllFunctionTags()) {
            lines.push_back("G|" + tag->getName() + "|" + tag->getComment());
        }
        auto it = program.getFunctionManager()->getFunctions();
        while (it.hasNext()) {
            Function* f = it.next();
            if (!f) continue;
            for (auto* tag : f->getTags()) {
                if (!tag) continue;
                std::ostringstream line;
                line << "GA|" << f->getEntryPoint().getOffset() << "|" << tag->getName();
                lines.push_back(line.str());
            }
        }
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
    auto fixtureBytes = buildFunctionTagFixture();
    auto reader = GbfReader::fromMemory(std::move(fixtureBytes));

    const GbfTableSchema* tagsTable = reader->findTable("Function Tags");
    const GbfTableSchema* mapTable = reader->findTable("Function Tag Map");
    const GbfTableSchema* symTable = reader->findTable("Symbols");
    const GbfTableSchema* fnTable = reader->findTable("Function Data");
    TEST("fixture: Function Tags table found", tagsTable != nullptr);
    TEST("fixture: Function Tag Map table found", mapTable != nullptr);
    TEST("fixture: Symbols table found", symTable != nullptr);
    TEST("fixture: Function Data table found", fnTable != nullptr);
    if (!tagsTable || !mapTable || !symTable || !fnTable) return 1;

    GzfProgramImporter importer(*reader);
    std::unique_ptr<ProgramDB> program = importer.import("tags_fixture.exe");
    const auto& st = importer.getStats();
    for (const auto& w : importer.getWarnings()) {
        std::cout << "  warn: " << w << "\n";
    }

    TEST("fixture: function imported", st.functions == 1);
    TEST("fixture: function tags imported", st.functionTags == 2);
    TEST("fixture: tag assignments applied", st.functionTagAssignments == 2);
    TEST("fixture: bad assignments counted", st.functionTagAssignmentsBad == 1);

    auto* ftm = program->getFunctionTagManager();
    TEST("fixture: tag manager present", ftm != nullptr);
    if (ftm) {
        FunctionTag* important = ftm->getFunctionTag("IMPORTANT");
        FunctionTag* entry = ftm->getFunctionTag("ENTRY");
        TEST("fixture: IMPORTANT tag exists", important != nullptr);
        TEST("fixture: ENTRY tag exists", entry != nullptr);
        TEST("fixture: IMPORTANT comment",
             important && important->getComment() == "vital code");
        TEST("fixture: ENTRY comment", entry && entry->getComment().empty());
        TEST("fixture: tag count", ftm->getAllFunctionTags().size() == 2);
    }

    auto* space = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());
    Address a1000(space, 0x1000);
    Function* f1 = program->getFunctionManager()->getFunctionAt(a1000);
    TEST("fixture: function F1 at 0x1000", f1 != nullptr);
    if (f1) {
        TEST("fixture: F1 name", f1->getName() == "F1");
        const auto& f1Tags = f1->getTags();
        TEST("fixture: F1 has 2 tags", f1Tags.size() == 2);
        bool hasImportant = false, hasEntry = false;
        for (auto* tag : f1Tags) {
            if (tag && tag->getName() == "IMPORTANT") hasImportant = true;
            if (tag && tag->getName() == "ENTRY") hasEntry = true;
        }
        TEST("fixture: F1 tagged IMPORTANT", hasImportant);
        TEST("fixture: F1 tagged ENTRY", hasEntry);
    }

    // ================================================================
    // 2. Snapshot round-trip (commit + reload)
    // ================================================================
    std::string stateA = tagState(*program);
    TEST("fixture: tag state dump non-empty", !stateA.empty());
    std::cout << "  tag state:\n" << stateA;

    std::string repoPath = makeTempRepo("ft");
    Repository::create(repoPath, "fidelity", "tags_fixture.exe", "0000",
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
    TEST("fixture: reload state identical", r1 && tagState(*r1) == stateA);
    if (r1 && tagState(*r1) != stateA) {
        std::cout << "  reloaded state:\n" << tagState(*r1);
    }
    fs::remove_all(repoPath);

    std::cout << "\n=== Gzf Function Tag Fidelity Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}