/* ###
 * IP: Enigma Engine (original work)
 *
 * Unit tests for GbfReader: container header, DBParms, block table, master
 * table decode, all supported node types (long-key varrec/fixedrec/interior,
 * var-key rec/interior, fixed-key variants), chained buffers and sparse
 * records.  Uses a synthetic .gbf fixture built by the test itself as well as
 * malformed input cases.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/import/GbfReader.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <string>
#include <vector>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace fs = std::filesystem;
using namespace ghidra;

namespace {

constexpr int kBlockSize = 512;
constexpr int kContentSize = kBlockSize - 5;  // 507

// Ghidra db.ChainedBuffer.XOR_MASK_BYTES (shared by both fixtures)
static const uint8_t kXorMask[128] = {
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8, 0xc3, 0x48, 0xdd, 0x8b,
    0x21, 0xd6, 0x94, 0x78, 0x35, 0xab, 0x2b, 0x7e, 0xb2, 0x4f, 0x82, 0x4e,
    0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e, 0x7e, 0xe6, 0xb6, 0xbd, 0x56, 0x91,
    0x57, 0x72, 0xe6, 0x91, 0xdc, 0x52, 0x2e, 0xf2, 0x1a, 0xb7, 0xd6, 0x6f,
    0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f, 0xf4, 0xdd, 0x11, 0xee,
    0xf2, 0x67, 0xfe, 0x48, 0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24,
    0x8e, 0x17, 0x76, 0x51, 0xe2, 0x60, 0xd7, 0xe6, 0x83, 0x65, 0xd5, 0xf0,
    0x7f, 0xf2, 0xa0, 0xd6, 0x4b, 0xbd, 0x24, 0xd8, 0xab, 0xea, 0x9e, 0xa6,
    0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc, 0x69, 0x11, 0xf8, 0x3c,
    0xa7, 0x3f, 0x5d, 0x77, 0x94, 0x3f, 0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56,
    0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40};

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

// big-endian serialization helpers used by the record builder
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

/**
 * Builds a synthetic Gbf database:
 *   block 0   DBParms (parm0 = master root buffer id 1)
 *   block 1   master table leaf (long-key varrec) with 5 records:
 *             USERS (long keys, Id Byte + Name String), VARS (string keys,
 *             Val Int), DATA (long keys, Blob Binary, single-node obfuscated
 *             chain), BIG (long keys, Blob Binary, indexed obfuscated chain),
 *             SPARSE (long keys, A Long + B String sparse)
 *   block 2   USERS root leaf: keys 0x10/0x20, records (id, name)
 *   block 3   VARS root (varkey rec leaf): keys "AAA"/"ZZZ"
 *   block 4   DATA root leaf: key 5, chained record -> data node 5
 *   block 5   chained data node (type 9, XOR-obfuscated) "hello chain"
 *   block 6   BIG root leaf: key 6, chained record -> index node 9
 *   block 7   chained data chunk A (type 9, obfuscated): 506 'X' bytes
 *   block 8   chained data chunk B (type 9, obfuscated): 298 'X' bytes
 *   block 9   chained index node (type 8): size 804|MSB, next=-1, ids [7, 8]
 *   block 10  SPARSE root leaf: one record with a sparse string column
 */
std::vector<uint8_t> buildFixture() {
    constexpr int kBlockCount = 11;

    auto maskAt = [&](size_t pos) -> uint8_t {
        return kXorMask[pos % 128];
    };
    std::vector<uint8_t> file(kBlockSize + kBlockCount * kBlockSize, 0);

    // header
    putU64(file, 0, GbfReader::kMagic);
    putU64(file, 8, 0x1122334455667788ULL);
    putU32(file, 16, 1);               // header version
    putU32(file, 20, kBlockSize);
    putU32(file, 24, kBlockCount + 1);  // first free id
    putU32(file, 28, 0);               // container parms

    std::vector<std::vector<uint8_t>> contents(kBlockCount,
        std::vector<uint8_t>(kContentSize, 0));

    // ---- block 0: DBParms: type(1)=9, dataLen(4)=9, version(1)=1, parm0=1
    contents[0][0] = 9;
    putU32(contents[0], 1, 9);
    contents[0][5] = 1;
    putU32(contents[0], 6, 1);  // master root buffer id

    // ---- master leaf (type 1): entries 13 + 5*13 = 78 bytes
    // record content: Name String, Version Int, RootBuf Int, KeyType Byte,
    //                 FieldTypes Binary, FieldNames String, IndexCol Int,
    //                 MaxKey Long, RecCount Int
    std::vector<std::vector<uint8_t>> masterRecs;
    auto masterRecord = [](const std::string& name, int32_t ver, int32_t root,
                            int32_t keyType, const std::vector<uint8_t>& fieldTypes,
                            const std::string& fieldNames) {
        std::vector<uint8_t> r;
        std::vector<uint8_t> t = strField(name);
        r.insert(r.end(), t.begin(), t.end());
        t = i32Field(ver); r.insert(r.end(), t.begin(), t.end());
        t = i32Field(root); r.insert(r.end(), t.begin(), t.end());
        t = i8Field(static_cast<int8_t>(keyType)); r.insert(r.end(), t.begin(), t.end());
        t = binField(fieldTypes); r.insert(r.end(), t.begin(), t.end());
        t = strField(fieldNames); r.insert(r.end(), t.begin(), t.end());
        t = i32Field(-1); r.insert(r.end(), t.begin(), t.end());
        t = i64Field(10); r.insert(r.end(), t.begin(), t.end());
        t = i32Field(2); r.insert(r.end(), t.begin(), t.end());
        return r;
    };
    masterRecs.push_back(masterRecord("USERS", 5, 2, 2, {0, 4}, "Id,Name"));
    masterRecs.push_back(masterRecord("VARS", 1, 3, 4, {2}, "Val"));
    masterRecs.push_back(masterRecord("DATA", 1, 4, 3, {5}, "Blob"));
    masterRecs.push_back(masterRecord("BIG", 1, 6, 3, {5}, "Blob"));
    masterRecs.push_back(
        masterRecord("SPARSE", 1, 10, 3, {3, 4, 2, 0xFF, 0x01, 0x01, 0xFF}, "A,B,C"));

    std::vector<uint8_t>& m = contents[1];
    m[0] = 1;
    putU32(m, 1, 5);  // key count
    size_t dataOff = kContentSize;
    for (int i = 4; i >= 0; i--) {
        std::vector<uint8_t>& r = masterRecs[static_cast<size_t>(i)];
        dataOff -= r.size();
        std::memcpy(&m[dataOff], r.data(), r.size());
        size_t e = 13 + static_cast<size_t>(i) * 13;
        putU64(m, e, static_cast<uint64_t>(i + 1));
        putU32(m, e + 8, static_cast<uint32_t>(dataOff));
        m[e + 12] = 0;
    }

    // ---- block 2: USERS leaf (type 1), keys 0x10/0x20
    std::vector<uint8_t>& u = contents[2];
    u[0] = 1;
    putU32(u, 1, 2);
    {
        std::vector<std::vector<uint8_t>> recs;
        std::vector<uint8_t> ra;
        ra.push_back(1);
        std::vector<uint8_t> t = strField("alice");
        ra.insert(ra.end(), t.begin(), t.end());
        recs.push_back(ra);
        std::vector<uint8_t> rb;
        rb.push_back(2);
        t = strField("bob");
        rb.insert(rb.end(), t.begin(), t.end());
        recs.push_back(rb);
        size_t off = kContentSize;
        for (int i = 1; i >= 0; i--) {
            off -= recs[static_cast<size_t>(i)].size();
            std::memcpy(&u[off], recs[static_cast<size_t>(i)].data(),
                recs[static_cast<size_t>(i)].size());
            size_t e = 13 + static_cast<size_t>(i) * 13;
            putU64(u, e, i ? 0x20 : 0x10);
            putU32(u, e + 8, static_cast<uint32_t>(off));
            u[e + 12] = 0;
        }
    }

    // ---- block 3: VARS varkey rec leaf (type 4), keys "AAA"/"ZZZ"
    std::vector<uint8_t>& v = contents[3];
    v[0] = 4;
    v[1] = 4;  // string key type
    putU32(v, 2, 2);
    {
        std::vector<uint8_t> key1 = strField("AAA");
        std::vector<uint8_t> rec1 = i32Field(11);
        std::vector<uint8_t> key2 = strField("ZZZ");
        std::vector<uint8_t> rec2 = i32Field(12);
        size_t off = kContentSize;
        off -= key2.size() + rec2.size();
        std::memcpy(&v[off], key2.data(), key2.size());
        std::memcpy(&v[off + key2.size()], rec2.data(), rec2.size());
        uint32_t koff2 = static_cast<uint32_t>(off);
        off -= key1.size() + rec1.size();
        std::memcpy(&v[off], key1.data(), key1.size());
        std::memcpy(&v[off + key1.size()], rec1.data(), rec1.size());
        uint32_t koff1 = static_cast<uint32_t>(off);
        putU32(v, 14, koff1);
        v[18] = 0;
        putU32(v, 19, koff2);
        v[23] = 0;
    }

    // ---- block 4: DATA leaf (type 1), key 5, chained record -> data node 5
    std::vector<uint8_t>& d = contents[4];
    d[0] = 1;
    putU32(d, 1, 1);
    {
        size_t e = 13;
        putU64(d, e, 5);
        putU32(d, e + 8, kContentSize - 4);
        d[e + 12] = 1;  // chained
        putU32(d, kContentSize - 4, 5);  // chain buffer id
    }

    // ---- block 5: single-node obfuscated chain (type 9): "hello chain"
    {
        std::vector<uint8_t> payload = binField({0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x63,
            0x68, 0x61, 0x69, 0x6e});  // "hello chain"
        std::vector<uint8_t>& c = contents[5];
        c[0] = 9;
        putU32(c, 1, 0x80000000u | static_cast<uint32_t>(payload.size()));  // MSB = obfuscated
        for (size_t i = 0; i < payload.size(); i++) {
            c[5 + i] = static_cast<uint8_t>(payload[i] ^ maskAt(i));
        }
    }

    // ---- block 6: BIG leaf (type 1), key 6, chained record -> index node 9
    std::vector<uint8_t>& big = contents[6];
    big[0] = 1;
    putU32(big, 1, 1);
    {
        size_t e = 13;
        putU64(big, e, 6);
        putU32(big, e + 8, kContentSize - 4);
        big[e + 12] = 1;  // chained
        putU32(big, kContentSize - 4, 9);  // chain index node id
    }

    // ---- blocks 7/8: obfuscated chained data chunks (type 9), data from
    //     offset 1. The chain holds the full record encoding: binary field =
    //     len(4) + 800 'X'; the mask restarts at each chunk boundary.
    constexpr size_t kChunkPayload = 506;  // kContentSize - 1
    constexpr size_t kPayloadLen = 800;
    constexpr size_t kBlobSize = 4 + kPayloadLen;  // record bytes in chain
    const size_t kChunkA = kChunkPayload;
    const size_t kChunkB = kBlobSize - kChunkA;
    std::vector<uint8_t>& ca = contents[7];
    ca[0] = 9;
    putU32(ca, 1, 0);  // chunk data nodes carry no meaningful length here
    for (size_t i = 0; i < 4; i++) {
        ca[1 + i] = static_cast<uint8_t>(((kPayloadLen >> (8 * (3 - i))) & 0xFF) ^ maskAt(i));
    }
    for (size_t i = 0; i < kChunkA - 4; i++) {
        size_t pos = 4 + i;
        ca[1 + pos] = static_cast<uint8_t>('X' ^ maskAt(pos));
    }
    std::vector<uint8_t>& cb = contents[8];
    cb[0] = 9;
    for (size_t i = 0; i < kChunkB; i++) {
        cb[1 + i] = static_cast<uint8_t>('X' ^ maskAt(i));
    }

    // ---- block 9: chained index node (type 8):
    //               size|MSB, nextIndexId=-1, data ids [7, 8]
    std::vector<uint8_t>& ix = contents[9];
    ix[0] = 8;
    putU32(ix, 1, 0x80000000u | static_cast<uint32_t>(kBlobSize));
    putU32(ix, 5, -1);
    putU32(ix, 9, 7);
    putU32(ix, 13, 8);

    // ---- block 10: SPARSE leaf (type 1), key 1, record: Long A + Int C +
    //               sparse tail: count=1, col=1, String "sparse!"
    std::vector<uint8_t>& s = contents[10];
    s[0] = 1;
    putU32(s, 1, 1);
    {
        std::vector<uint8_t> rec = i64Field(7);
        std::vector<uint8_t> zero = i32Field(0);  // col 2 (C), non-sparse Int
        rec.insert(rec.end(), zero.begin(), zero.end());
        rec.push_back(1);  // sparse count
        rec.push_back(1);  // column index 1 (B, sparse)
        std::vector<uint8_t> st = strField("sparse!");
        rec.insert(rec.end(), st.begin(), st.end());
        size_t off = kContentSize - rec.size();
        std::memcpy(&s[off], rec.data(), rec.size());
        putU64(s, 13, 1);
        putU32(s, 21, static_cast<uint32_t>(off));
        s[25] = 0;
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

/**
 * Builds a gbf focused on chained buffers (no master records):
 *   block 0   DBParms (parm0 = 1)
 *   block 1   master table leaf (type 1) with zero records
 *   block 2   chained index node (head, type 8): size 75908|MSB, next=3,
 *             chunk ids 4..127 with id 100 = -1 (unallocated)
 *   block 3   chained index node (tail, type 8): next=-1, chunk ids 128..154
 *   blocks    chained data nodes (type 9, XOR-obfuscated): one per chunk;
 *   4..154    chunk payload 506 bytes, mask restarts per chunk; the last
 *             chunk holds 8 bytes; chunk 100 has no block (unallocated).
 * Chain payload byte j = (j*7+3)&0xFF so padding/mask errors are caught.
 */
std::vector<uint8_t> buildChainFixture() {
    constexpr size_t kChunkPayload = 506;
    constexpr size_t kChunkCount = 151;        // 150 full + 8-byte tail
    constexpr size_t kChainSize = 150 * kChunkPayload + 8;  // 75908
    constexpr int kBlockCount = 155;           // ids 0..154

    auto payloadByte = [](size_t j) { return static_cast<uint8_t>((j * 7 + 3) & 0xFF); };
    auto maskAt = [](size_t pos) { return kXorMask[pos % 128]; };

    std::vector<uint8_t> file(kBlockSize + kBlockCount * kBlockSize, 0);
    putU64(file, 0, GbfReader::kMagic);
    putU64(file, 8, 0x99AABBCCDDEEFF00ULL);
    putU32(file, 16, 1);
    putU32(file, 20, kBlockSize);
    putU32(file, 24, kBlockCount);
    putU32(file, 28, 0);

    std::vector<std::vector<uint8_t>> contents(kBlockCount,
        std::vector<uint8_t>(kContentSize, 0));

    // DBParms -> master root buffer 1
    contents[0][0] = 9;
    putU32(contents[0], 1, 9);
    contents[0][5] = 1;
    putU32(contents[0], 6, 1);

    // empty master leaf
    contents[1][0] = 1;
    putU32(contents[1], 1, 0);

    // head index node: 124 ids (chunks 0..123), chunk 100 unallocated
    std::vector<uint8_t>& h = contents[2];
    h[0] = 8;
    putU32(h, 1, 0x80000000u | static_cast<uint32_t>(kChainSize));  // obfuscated
    putU32(h, 5, 3);  // nextIndexId
    for (size_t i = 0; i < 124; i++) {
        putU32(h, 9 + 4 * i, i == 100 ? -1 : static_cast<int32_t>(4 + i));
    }

    // tail index node: 27 ids (chunks 124..150)
    std::vector<uint8_t>& t = contents[3];
    t[0] = 8;
    putU32(t, 1, 0);
    putU32(t, 5, -1);  // nextIndexId
    for (size_t i = 0; i < 27; i++) {
        putU32(t, 9 + 4 * i, static_cast<int32_t>(128 + i));
    }

    // data chunks
    for (size_t i = 0; i < kChunkCount; i++) {
        if (i == 100) {
            continue;
        }
        int32_t id = i < 124 ? static_cast<int32_t>(4 + i) : static_cast<int32_t>(128 + (i - 124));
        size_t len = i < 150 ? kChunkPayload : kChainSize - 150 * kChunkPayload;
        std::vector<uint8_t>& c = contents[static_cast<size_t>(id)];
        c[0] = 9;
        for (size_t k = 0; k < len; k++) {
            c[1 + k] = static_cast<uint8_t>(payloadByte(i * kChunkPayload + k) ^ maskAt(k));
        }
    }

    for (int i = 0; i < kBlockCount; i++) {
        size_t base = static_cast<size_t>(i + 1) * kBlockSize;
        file[base] = 0;
        putU32(file, base + 1, static_cast<uint32_t>(i));
        std::memcpy(&file[base + 5], contents[static_cast<size_t>(i)].data(), kContentSize);
    }
    return file;
}

std::string tempFilePath(const char* name) {
    auto path = fs::temp_directory_path() / name;
    return path.string();
}

}  // namespace

int main() {
    std::vector<uint8_t> fixture = buildFixture();
    std::string path = tempFilePath("enigma_gbf_fixture.gbf");
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(fixture.data()),
            static_cast<std::streamsize>(fixture.size()));
    }
    {
        std::string badPath = tempFilePath("enigma_gbf_fixture_bad.gbf");
        {
            std::ofstream out(badPath, std::ios::binary);
            out.write("not a gbf file at all, but long enough to test magic", 50);
        }
        TEST("isGbfFile false on junk", !GbfReader::isGbfFile(badPath));
        TEST("isGbfFile true on fixture", GbfReader::isGbfFile(path));
        bool threw = false;
        try {
            GbfReader gbf(badPath);
        } catch (const std::exception&) {
            threw = true;
        }
        TEST("ctor throws on bad magic", threw);
        fs::remove(badPath);
    }

    {
        GbfReader gbf(path);
        TEST("fileId parsed", gbf.fileId() == 0x1122334455667788ULL);
        TEST("blockSize parsed", gbf.blockSize() == kBlockSize);
        TEST("firstFreeId parsed", gbf.firstFreeBufferId() == 12);
        TEST("DBParms has MasterTableBufferId",
            !gbf.parameters().empty() &&
            gbf.parameters().front().first == "MasterTableBufferId" &&
            gbf.parameters().front().second == 1);

        TEST("master table has 5 tables", gbf.tables().size() == 5);

        const GbfTableSchema* users = gbf.findTable("USERS");
        TEST("findTable USERS", users != nullptr);
        if (users) {
            TEST("USERS keySize", users->keySize() == 4);
            TEST("USERS fixedRecordSize variable",
                users->fixedRecordSize() == -1);
            TEST("USERS version", users->version == 5);
            TEST("USERS root id", users->rootBufferId == 2);
            TEST("USERS columns", users->fieldTypes.size() == 2 &&
                users->fieldTypes[0] == GbfFieldType::Byte &&
                users->fieldTypes[1] == GbfFieldType::String);
            TEST("USERS field names", users->fieldNames.size() == 2 &&
                users->fieldNames[0] == "Id" && users->fieldNames[1] == "Name");
            TEST("USERS not index table", !users->isIndexTable());
            TEST("USERS no sparse", !users->hasSparseColumns());

            int recordCount = 0;
            bool sawAlice = false, sawBob = false;
            gbf.visitRecords(*users, [&](const GbfRecord& rec) {
                recordCount++;
                size_t off = 0;
                int64_t id = GbfReader::readNumField(GbfFieldType::Byte, rec.data.data(),
                    rec.data.size(), off);
                std::string name;
                GbfReader::readStringField(rec.data.data(), rec.data.size(), off, name);
                if (id == 1 && name == "alice") sawAlice = true;
                if (id == 2 && name == "bob") sawBob = true;
            });
            TEST("USERS record count", recordCount == 2);
            TEST("USERS record contents", sawAlice && sawBob);
        }

        const GbfTableSchema* vars = gbf.findTable("VARS");
        TEST("findTable VARS", vars != nullptr);
        if (vars) {
            TEST("VARS variable key", vars->keySize() == -1);
            std::vector<std::string> keys;
            std::vector<int64_t> vals;
            gbf.visitRecords(*vars, [&](const GbfRecord& rec) {
                keys.emplace_back(rec.key.begin(), rec.key.end());
                size_t off = 0;
                vals.push_back(GbfReader::readNumField(GbfFieldType::Int, rec.data.data(),
                    rec.data.size(), off));
            });
            TEST("VARS keys", keys.size() == 2 && keys[0] == "AAA" && keys[1] == "ZZZ");
            if (!(keys.size() == 2 && keys[0] == "AAA" && keys[1] == "ZZZ")) {
                std::cerr << "  debug keys: [";
                for (const auto& k : keys) {
                    std::cerr << "('" << k << "' len=" << k.size() << ") ";
                }
                std::cerr << "]\n";
            }
            TEST("VARS values", vals.size() == 2 && vals[0] == 11 && vals[1] == 12);
        }

        const GbfTableSchema* data = gbf.findTable("DATA");
        TEST("findTable DATA", data != nullptr);
        if (data) {
            TEST("DATA key size", data->keySize() == 8);
            int recordCount = 0;
            std::string blob;
            gbf.visitRecords(*data, [&](const GbfRecord& rec) {
                recordCount++;
                size_t off = 0;
                std::vector<uint8_t> b = GbfReader::readBinaryField(rec.data.data(),
                    rec.data.size(), off);
                blob.assign(b.begin(), b.end());
            });
            TEST("DATA chained record decoded",
                recordCount == 1 && blob == "hello chain");

        const GbfTableSchema* big = gbf.findTable("BIG");
        TEST("findTable BIG", big != nullptr);
        if (big) {
            TEST("BIG key size", big->keySize() == 8);
            int bigCount = 0;
            std::string bigBlob;
            gbf.visitRecords(*big, [&](const GbfRecord& rec) {
                bigCount++;
                size_t off = 0;
                std::vector<uint8_t> b = GbfReader::readBinaryField(rec.data.data(),
                    rec.data.size(), off);
                bigBlob.assign(b.begin(), b.end());
            });
            TEST("BIG chained record decoded", bigCount == 1 && bigBlob.size() == 800 &&
                std::all_of(bigBlob.begin(), bigBlob.end(), [](char c) { return c == 'X'; }));
        }
        }

        const GbfTableSchema* sparse = gbf.findTable("SPARSE");
        TEST("findTable SPARSE", sparse != nullptr);
        if (sparse) {
            TEST("SPARSE sparse columns", sparse->hasSparseColumns() &&
                sparse->sparseColumns.size() == 1 && sparse->sparseColumns[0] == 1);
            std::vector<GbfRecord> recs;
            gbf.visitRecords(*sparse, [&](const GbfRecord& rec) { recs.push_back(rec); });
            TEST("SPARSE record count", recs.size() == 1);
            if (recs.size() == 1) {
                size_t off = 0;
                int64_t a = GbfReader::readNumField(GbfFieldType::Long, recs[0].data.data(),
                    recs[0].data.size(), off);
                TEST("SPARSE non-sparse column", a == 7);
                TEST("SPARSE sparse column split", recs[0].sparseFields.size() == 1 &&
                    recs[0].sparseFields[0].first == 1);
                if (!(recs[0].sparseFields.size() == 1 && recs[0].sparseFields[0].first == 1)) {
                    std::cerr << "  debug sparseFields: " << recs[0].sparseFields.size() << " entries, data size " << recs[0].data.size() << " bytes:\n";
                    for (const auto& sf : recs[0].sparseFields) {
                        std::cerr << "    col=" << sf.first << " valueBytes=" << sf.second.size() << "\n";
                    }
                }
                if (recs[0].sparseFields.size() == 1) {
                    std::string value;
                    GbfReader::formatField(GbfFieldType::String,
                        recs[0].sparseFields[0].second.data(),
                        recs[0].sparseFields[0].second.size(), 0, value);
                    TEST("SPARSE sparse value", value == "\"sparse!\"");
                }
            }
        }
    }

    {
        // in-memory variant must behave identically
        std::unique_ptr<GbfReader> gbf = GbfReader::fromMemory(fixture);
        TEST("fromMemory tables", gbf->tables().size() == 5);
        const GbfTableSchema* users = gbf->findTable("USERS");
        TEST("fromMemory findTable", users != nullptr);
        if (users) {
            int recordCount = 0;
            gbf->visitRecords(*users, [&](const GbfRecord&) { recordCount++; });
            TEST("fromMemory records", recordCount == 2);
        }
    }

    {
        // chained-buffer stress fixture: multi-index-node chain (nextIndexId),
        // unallocated chunk (id -1), XOR mask restarting per chunk
        std::vector<uint8_t> chainFile = buildChainFixture();
        std::unique_ptr<GbfReader> gbf = GbfReader::fromMemory(chainFile);

        TEST("chain fixture firstFreeId", gbf->firstFreeBufferId() == 155);
        TEST("chain fixture empty master", gbf->tables().empty());

        bool threw = false;
        try {
            gbf->readChainedBuffer(104);  // zero block, not a chained node
        } catch (const std::exception&) {
            threw = true;
        }
        TEST("readChainedBuffer on non-chain block throws", threw);

        constexpr size_t kChainSize = 75908;
        constexpr size_t kChunkPayload = 506;
        std::vector<uint8_t> chain = gbf->readChainedBuffer(2);
        TEST("multi-index chain size", chain.size() == kChainSize);

        bool contentsOk = chain.size() == kChainSize;
        for (size_t j = 0; contentsOk && j < kChainSize; j++) {
            size_t chunk = j / kChunkPayload;
            size_t local = j % kChunkPayload;
            uint8_t expected = (chunk == 100) ? kXorMask[local % 128]
                                              : static_cast<uint8_t>((j * 7 + 3) & 0xFF);
            if (chain[j] != expected) {
                contentsOk = false;
            }
        }
        TEST("multi-index chain contents", contentsOk);

        bool unallocOk = true;
        for (size_t k = 0; k < kChunkPayload; k++) {
            if (chain[100 * kChunkPayload + k] != kXorMask[k % 128]) {
                unallocOk = false;
            }
        }
        TEST("multi-index chain unallocated chunk", unallocOk);
    }

    fs::remove(path);

    std::cout << "\n=== GbfReader Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}