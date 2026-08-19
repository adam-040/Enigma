/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/import/GbfReader.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace ghidra {

namespace {

constexpr uint8_t kEmptyBlockFlag = 0x01;

constexpr size_t kHeaderSize = 32;

constexpr int32_t kFieldExtensionIndicator = -1;
constexpr int32_t kSparseFieldListExtension = 1;

// DBParms layout inside block 0 content (db.DBParms)
constexpr size_t kDbParmsBaseOffset = 6;  // int parms; parm 0 = master table root id

// Master table column order (db.MasterTable)
constexpr size_t kMasterName = 0;
constexpr size_t kMasterVersion = 1;
constexpr size_t kMasterRootBuf = 2;
constexpr size_t kMasterKeyType = 3;
constexpr size_t kMasterFieldTypes = 4;
constexpr size_t kMasterFieldNames = 5;
constexpr size_t kMasterIndexCol = 6;
constexpr size_t kMasterMaxKey = 7;
constexpr size_t kMasterRecCount = 8;
constexpr size_t kMasterColCount = 9;

uint64_t beU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

int32_t beI32(const uint8_t* p) {
    return static_cast<int32_t>(beU64(p) >> 32 & 0xFFFFFFFFu);
}

int64_t beI64(const uint8_t* p) {
    return static_cast<int64_t>(beU64(p));
}

int32_t fieldSize(GbfFieldType t) {
    switch (t) {
        case GbfFieldType::Byte:
        case GbfFieldType::Bool:
            return 1;
        case GbfFieldType::Short:
            return 2;
        case GbfFieldType::Int:
            return 4;
        case GbfFieldType::Long:
            return 8;
        case GbfFieldType::Fixed10:
            return 10;
        case GbfFieldType::String:
        case GbfFieldType::Binary:
            break;
    }
    return -1;
}

GbfFieldType lowNibble(int32_t code) {
    return static_cast<GbfFieldType>(code & 0x0F);
}

GbfFieldType highNibble(int32_t code) {
    return static_cast<GbfFieldType>((code >> 4) & 0x0F);
}

/**
 * Advances `off` past one key value of the given key type code (plain field
 * code, or indexed (primary<<4)|indexed: indexed field bytes then primary key
 * bytes).  Bounds are enforced; bad data throws.
 */
void advanceKeyBytes(int32_t code, const uint8_t* p, size_t size, size_t& off) {
    auto skipOne = [&](GbfFieldType t) {
        int32_t len = fieldSize(t);
        if (len >= 0) {
            if (off + static_cast<size_t>(len) > size) {
                throw std::runtime_error("Gbf: key field out of bounds");
            }
            off += static_cast<size_t>(len);
        } else if (t == GbfFieldType::String) {
            std::string s;
            GbfReader::readStringField(p, size, off, s);
        } else if (t == GbfFieldType::Binary) {
            GbfReader::readBinaryField(p, size, off);
        }
    };
    if ((code & 0xF0) == 0) {
        skipOne(lowNibble(code));
    } else {
        skipOne(lowNibble(code));
        skipOne(highNibble(code));
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// GbfTableSchema
// ---------------------------------------------------------------------------

int32_t GbfTableSchema::keySize() const {
    if (isIndexTable()) {
        int32_t a = fieldSize(lowNibble(keyTypeCode));
        int32_t b = fieldSize(highNibble(keyTypeCode));
        return (a < 0 || b < 0) ? -1 : a + b;
    }
    return fieldSize(lowNibble(keyTypeCode));
}

int32_t GbfTableSchema::fixedRecordSize() const {
    int32_t total = 0;
    for (GbfFieldType t : fieldTypes) {
        int32_t s = fieldSize(t);
        if (s < 0) {
            return -1;
        }
        total += s;
    }
    return total;
}

// ---------------------------------------------------------------------------
// GbfReader: construction
// ---------------------------------------------------------------------------

bool GbfReader::isGbfFile(const std::string& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in) {
        return false;
    }
    uint8_t hdr[8] = {};
    in.read(reinterpret_cast<char*>(hdr), 8);
    if (in.gcount() != 8) {
        return false;
    }
    return beU64(hdr) == kMagic;
}

GbfReader::GbfReader(const std::string& filePath)
    : GbfReader([](const std::string& path) {
          std::ifstream in(path, std::ios::binary | std::ios::ate);
          if (!in) {
              throw std::runtime_error("Gbf: cannot open file: " + path);
          }
          std::streamsize n = in.tellg();
          if (n <= 0) {
              throw std::runtime_error("Gbf: empty file: " + path);
          }
          std::vector<uint8_t> bytes(static_cast<size_t>(n));
          in.seekg(0);
          in.read(reinterpret_cast<char*>(bytes.data()), n);
          if (!in) {
              throw std::runtime_error("Gbf: failed to read file: " + path);
          }
          return bytes;
      }(filePath)) {
}

std::unique_ptr<GbfReader> GbfReader::fromMemory(std::vector<uint8_t> bytes) {
    return std::unique_ptr<GbfReader>(new GbfReader(std::move(bytes)));
}

GbfReader::GbfReader(std::vector<uint8_t> bytes) : fileBytes_(std::move(bytes)) {
    decodeHeader();
    readBlocks();

    // DBParms lives in the content of block 0; its first int parameter is the
    // master table root buffer id (db.DBParms MASTER_TABLE_ROOT_BUFFER_ID).
    const std::vector<uint8_t>& b0 = block(0);
    if (b0.size() < kDbParmsBaseOffset + 4) {
        throw std::runtime_error("Gbf: DBParms block too small");
    }
    size_t off = kDbParmsBaseOffset;
    size_t parmEnd = 5 + static_cast<size_t>(beI32(&b0[1]));
    if (parmEnd > b0.size()) {
        parmEnd = b0.size();
    }
    static const char* kParmNames[] = {"MasterTableBufferId", "DatabaseIdHigh", "DatabaseIdLow"};
    int parmIndex = 0;
    while (off + 4 <= parmEnd) {
        int32_t value = beI32(&b0[off]);
        off += 4;
        std::string name =
            parmIndex < 3 ? kParmNames[parmIndex] : "Parm" + std::to_string(parmIndex);
        parms_.emplace_back(std::move(name), value);
        parmIndex++;
    }
    if (parms_.empty()) {
        throw std::runtime_error("Gbf: DBParms has no parameters");
    }
    int32_t masterRoot = parms_.front().second;
    if (masterRoot <= 0 || masterRoot >= static_cast<int32_t>(blocks_.size())) {
        throw std::runtime_error("Gbf: invalid master table root buffer id " +
            std::to_string(masterRoot));
    }
    decodeMasterTable();
}

void GbfReader::decodeHeader() {
    if (fileBytes_.size() < kHeaderSize) {
        throw std::runtime_error("Gbf: file too small");
    }
    const uint8_t* hdr = fileBytes_.data();
    if (beU64(hdr) != kMagic) {
        throw std::runtime_error("Gbf: bad magic");
    }
    fileId_ = beU64(hdr + 8);
    headerVersion_ = beI32(hdr + 16);
    blockSize_ = beI32(hdr + 20);
    firstFreeId_ = beI32(hdr + 24);
    int32_t numParms = beI32(hdr + 28);

    if (blockSize_ < 64 || static_cast<size_t>(blockSize_) > fileBytes_.size()) {
        throw std::runtime_error("Gbf: invalid block size " + std::to_string(blockSize_));
    }
    if (fileBytes_.size() % blockSize_ != 0) {
        throw std::runtime_error("Gbf: file size not a multiple of block size");
    }

    // Container parameter entries: int nameLen, name bytes, int value.
    size_t off = kHeaderSize;
    for (int i = 0; i < numParms; i++) {
        if (off + 4 > fileBytes_.size()) {
            throw std::runtime_error("Gbf: truncated container parms");
        }
        int32_t nameLen = beI32(&fileBytes_[off]);
        off += 4;
        if (nameLen < 0 || nameLen > static_cast<int32_t>(blockSize_) ||
            off + static_cast<size_t>(nameLen) + 4 > fileBytes_.size()) {
            throw std::runtime_error("Gbf: malformed container parm");
        }
        std::string name(reinterpret_cast<const char*>(&fileBytes_[off]),
            static_cast<size_t>(nameLen));
        off += static_cast<size_t>(nameLen);
        int32_t value = beI32(&fileBytes_[off]);
        off += 4;
        parms_.emplace_back(std::move(name), value);
    }
}

void GbfReader::readBlocks() {
    size_t blockCount = fileBytes_.size() / blockSize_ - 1;
    blocks_.assign(blockCount, std::vector<uint8_t>());
    for (size_t i = 0; i < blockCount; i++) {
        const uint8_t* p = fileBytes_.data() + (i + 1) * blockSize_;
        uint8_t flags = p[0];
        int32_t id = beI32(p + 1);
        if (id < 0 || static_cast<size_t>(id) >= blockCount) {
            throw std::runtime_error("Gbf: block at file slot " + std::to_string(i) +
                " has invalid buffer id " + std::to_string(id));
        }
        if ((flags & kEmptyBlockFlag) == 0) {
            blocks_[static_cast<size_t>(id)] = std::vector<uint8_t>(p + 5, p + blockSize_);
        }
    }
}

const std::vector<uint8_t>& GbfReader::block(int32_t id) const {
    if (id < 0 || static_cast<size_t>(id) >= blocks_.size()) {
        throw std::runtime_error("Gbf: buffer id out of range: " + std::to_string(id));
    }
    return blocks_[static_cast<size_t>(id)];
}

// ---------------------------------------------------------------------------
// Chained buffers
// ---------------------------------------------------------------------------

namespace {

// Ghidra fixed obfuscation mask (db.ChainedBuffer.XOR_MASK_BYTES): stored data
// is XOR'd with this table at the data-area offset modulo its length, and the
// mask sequence restarts at the beginning of each data node.
const uint8_t kXorMask[128] = {
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

void xorMask(std::vector<uint8_t>& out, size_t begin, size_t end) {
    for (size_t i = begin; i < end; i++) {
        out[i] ^= kXorMask[(i - begin) % sizeof(kXorMask)];
    }
}

}  // namespace

std::vector<uint8_t> GbfReader::readChainedBuffer(int32_t bufferId) const {
    const std::vector<uint8_t>& first = block(bufferId);
    if (first.empty()) {
        return {};
    }
    uint8_t nt = first[0];
    if (nt == static_cast<uint8_t>(GbfNodeType::ChainedBufferData)) {
        int32_t dataLen = beI32(&first[1]);
        bool obfuscated = dataLen < 0;
        if (obfuscated) {
            dataLen &= 0x7FFFFFFF;
        }
        size_t end = 5 + static_cast<size_t>(dataLen);
        if (end > first.size()) {
            end = first.size();
        }
        std::vector<uint8_t> result(first.begin() + 5, first.begin() + end);
        if (obfuscated) {
            xorMask(result, 0, result.size());
        }
        return result;
    }
    if (nt == static_cast<uint8_t>(GbfNodeType::ChainedBufferIndex)) {
        int32_t size = beI32(&first[1]);
        bool obfuscated = size < 0;
        if (obfuscated) {
            size &= 0x7FFFFFFF;
        }
        std::vector<uint8_t> result;
        result.reserve(static_cast<size_t>(size));
        const size_t dataSpace = blockSize_ - 6;  // data buffer = block-5, 1 type byte
        int32_t indexBuf = bufferId;
        while (true) {
            const std::vector<uint8_t>& ib = block(indexBuf);
            if (ib.empty()) {
                break;
            }
            if (ib[0] != static_cast<uint8_t>(GbfNodeType::ChainedBufferIndex)) {
                throw std::runtime_error("Gbf: bad chained index node " + std::to_string(indexBuf));
            }
            int32_t nextIndexId = beI32(&ib[5]);
            size_t off = 9;
            while (off + 4 <= ib.size()) {
                int32_t dataId = beI32(&ib[off]);
                off += 4;
                size_t chunkLen = dataSpace;
                if (result.size() + chunkLen > static_cast<size_t>(size)) {
                    chunkLen = static_cast<size_t>(size) - result.size();
                }
                size_t chunkBegin = result.size();
                if (dataId < 0) {
                    result.insert(result.end(), chunkLen, 0);
                } else {
                    const std::vector<uint8_t>& db = block(dataId);
                    if (db.empty() ||
                        db[0] != static_cast<uint8_t>(GbfNodeType::ChainedBufferData)) {
                        throw std::runtime_error("Gbf: bad chained data node " +
                            std::to_string(dataId));
                    }
                    size_t avail = db.size() > 1 ? db.size() - 1 : 0;
                    size_t take = chunkLen < avail ? chunkLen : avail;
                    result.insert(result.end(), db.begin() + 1, db.begin() + 1 + take);
                    if (take < chunkLen) {
                        result.insert(result.end(), chunkLen - take, 0);
                    }
                }
                if (obfuscated) {
                    xorMask(result, chunkBegin, result.size());
                }
                if (result.size() >= static_cast<size_t>(size)) {
                    return result;
                }
            }
            if (nextIndexId < 0) {
                break;
            }
            indexBuf = nextIndexId;
        }
        return result;
    }
    throw std::runtime_error("Gbf: buffer " + std::to_string(bufferId) +
        " is not a chained buffer (type " + std::to_string(nt) + ")");
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

int64_t GbfReader::readNumField(GbfFieldType type, const uint8_t* p, size_t size, size_t& off) {
    int32_t len = fieldSize(type);
    if (len < 0 || off + static_cast<size_t>(len) > size) {
        throw std::runtime_error("Gbf: numeric field out of bounds");
    }
    int64_t v = 0;
    switch (type) {
        case GbfFieldType::Byte:
            v = static_cast<int8_t>(p[off]);
            break;
        case GbfFieldType::Short:
            v = static_cast<int16_t>(beI32(p + off));
            break;
        case GbfFieldType::Int:
            v = beI32(p + off);
            break;
        case GbfFieldType::Long:
            v = beI64(p + off);
            break;
        case GbfFieldType::Bool:
            v = p[off] != 0;
            break;
        default:
            throw std::runtime_error("Gbf: not a numeric field type");
    }
    off += static_cast<size_t>(len);
    return v;
}

bool GbfReader::readStringField(const uint8_t* p, size_t size, size_t& off, std::string& value) {
    if (off + 4 > size) {
        throw std::runtime_error("Gbf: string length out of bounds");
    }
    int32_t len = beI32(p + off);
    off += 4;
    value.clear();
    if (len < 0) {
        return false;
    }
    if (off + static_cast<size_t>(len) > size) {
        throw std::runtime_error("Gbf: string data out of bounds");
    }
    value.assign(reinterpret_cast<const char*>(p + off), static_cast<size_t>(len));
    off += static_cast<size_t>(len);
    return true;
}

std::vector<uint8_t> GbfReader::readBinaryField(const uint8_t* p, size_t size, size_t& off) {
    if (off + 4 > size) {
        throw std::runtime_error("Gbf: binary length out of bounds");
    }
    int32_t len = beI32(p + off);
    off += 4;
    if (len < 0) {
        return {};
    }
    if (off + static_cast<size_t>(len) > size) {
        throw std::runtime_error("Gbf: binary data out of bounds");
    }
    std::vector<uint8_t> out(p + off, p + off + len);
    off += static_cast<size_t>(len);
    return out;
}

std::vector<uint8_t> GbfReader::readFixed10Field(const uint8_t* p, size_t size, size_t& off) {
    if (off + 10 > size) {
        throw std::runtime_error("Gbf: fixed10 field out of bounds");
    }
    std::vector<uint8_t> out(p + off, p + off + 10);
    off += 10;
    return out;
}

static void appendHex(std::string& out, const uint8_t* p, size_t n) {
    static const char* kHex = "0123456789abcdef";
    out += '0';
    out += 'x';
    for (size_t i = 0; i < n; i++) {
        out += kHex[p[i] >> 4];
        out += kHex[p[i] & 0xF];
    }
}

size_t GbfReader::formatField(GbfFieldType type, const uint8_t* p, size_t size, size_t off,
    std::string& out) {
    switch (type) {
        case GbfFieldType::Byte:
        case GbfFieldType::Short:
        case GbfFieldType::Int:
        case GbfFieldType::Long: {
            int64_t v = readNumField(type, p, size, off);
            out += std::to_string(v);
            break;
        }
        case GbfFieldType::Bool: {
            int64_t v = readNumField(type, p, size, off);
            out += v ? "true" : "false";
            break;
        }
        case GbfFieldType::String: {
            std::string s;
            if (readStringField(p, size, off, s)) {
                out += '"';
                out += s;
                out += '"';
            } else {
                out += "null";
            }
            break;
        }
        case GbfFieldType::Binary: {
            std::vector<uint8_t> b = readBinaryField(p, size, off);
            if (b.empty()) {
                out += "null";
            } else {
                out += "[bytes " + std::to_string(b.size()) + "] 0x";
                appendHex(out, b.data(), b.size());
            }
            break;
        }
        case GbfFieldType::Fixed10: {
            std::vector<uint8_t> b = readFixed10Field(p, size, off);
            appendHex(out, b.data(), b.size());
            break;
        }
    }
    return off;
}

// ---------------------------------------------------------------------------
// Record traversal
// ---------------------------------------------------------------------------

const GbfTableSchema* GbfReader::findTable(const std::string& name) const {
    for (const GbfTableSchema& t : tables_) {
        if (t.name == name) {
            return &t;
        }
    }
    return nullptr;
}

namespace {

/**
 * Splits the sparse tail out of a record: skips the non-sparse column region,
 * then parses the tail as byteCount + [byte colIndex, field bytes]* pairs.
 * Returns the per-column raw value bytes for the sparse columns.
 */
std::vector<std::pair<int32_t, std::vector<uint8_t>>> splitSparse(
    const std::vector<uint8_t>& data, const GbfTableSchema& table) {
    std::vector<std::pair<int32_t, std::vector<uint8_t>>> out;
    if (!table.hasSparseColumns()) {
        return out;
    }
    size_t off = 0;
    for (size_t c = 0; c < table.fieldTypes.size(); c++) {
        if (std::find(table.sparseColumns.begin(), table.sparseColumns.end(),
                static_cast<int32_t>(c)) != table.sparseColumns.end()) {
            continue;
        }
        GbfFieldType t = table.fieldTypes[c];
        int32_t len = fieldSize(t);
        if (len >= 0) {
            if (off + static_cast<size_t>(len) > data.size()) {
                throw std::runtime_error("Gbf: record field out of bounds");
            }
            off += static_cast<size_t>(len);
        } else if (t == GbfFieldType::String) {
            std::string s;
            GbfReader::readStringField(data.data(), data.size(), off, s);
        } else if (t == GbfFieldType::Binary) {
            GbfReader::readBinaryField(data.data(), data.size(), off);
        }
    }
    if (off >= data.size()) {
        return out;
    }
    int count = data[off++];
    for (int i = 0; i < count; i++) {
        if (off >= data.size()) {
            throw std::runtime_error("Gbf: sparse tail truncated");
        }
        int32_t col = data[off++];
        if (col < 0 || static_cast<size_t>(col) >= table.fieldTypes.size() ||
            std::find(table.sparseColumns.begin(), table.sparseColumns.end(), col) ==
                table.sparseColumns.end()) {
            throw std::runtime_error("Gbf: bad sparse column index " + std::to_string(col));
        }
        GbfFieldType t = table.fieldTypes[static_cast<size_t>(col)];
        int32_t len = fieldSize(t);
        size_t start = off;
        if (len >= 0) {
            if (off + static_cast<size_t>(len) > data.size()) {
                throw std::runtime_error("Gbf: sparse field out of bounds");
            }
            off += static_cast<size_t>(len);
        } else if (t == GbfFieldType::String) {
            std::string s;
            GbfReader::readStringField(data.data(), data.size(), off, s);
        } else if (t == GbfFieldType::Binary) {
            GbfReader::readBinaryField(data.data(), data.size(), off);
        }
        out.emplace_back(col, std::vector<uint8_t>(data.begin() + start, data.begin() + off));
    }
    return out;
}

}  // namespace

void GbfReader::decodeMasterTable() {
    // The master table itself is a normal long-key table (db.MasterTable):
    // Name(String), Version(Int), RootBufID(Int), KeyType(Byte),
    // FieldTypes(Binary), FieldNames(String), IndexColumn(Int), MaxKey(Long),
    // RecordCount(Int).
    GbfTableSchema master;
    master.name = "$master";
    master.rootBufferId = parms_.front().second;
    master.keyTypeCode = 3;  // long keys
    master.fieldTypes = {GbfFieldType::String, GbfFieldType::Int, GbfFieldType::Int,
        GbfFieldType::Byte, GbfFieldType::Binary, GbfFieldType::String, GbfFieldType::Int,
        GbfFieldType::Long, GbfFieldType::Int};
    master.fieldNames = {"Name", "Version", "RootBufID", "KeyType", "FieldTypes", "FieldNames",
        "IndexColumn", "MaxKey", "RecordCount"};

    collectRecords(master, [&](const GbfRecord& rec) {
        std::vector<std::string> strCols(kMasterColCount);
        std::vector<std::vector<uint8_t>> binCols(kMasterColCount);
        std::vector<int64_t> numCols(kMasterColCount, 0);

        size_t off = 0;
        for (size_t c = 0; c < kMasterColCount; c++) {
            GbfFieldType t = master.fieldTypes[c];
            const uint8_t* p = rec.data.data();
            size_t sz = rec.data.size();
            switch (t) {
                case GbfFieldType::String:
                    readStringField(p, sz, off, strCols[c]);
                    break;
                case GbfFieldType::Binary:
                    binCols[c] = readBinaryField(p, sz, off);
                    break;
                default:
                    numCols[c] = readNumField(t, p, sz, off);
                    break;
            }
        }

        GbfTableSchema table;
        table.name = strCols[kMasterName];
        table.version = static_cast<int32_t>(numCols[kMasterVersion]);
        table.rootBufferId = static_cast<int32_t>(numCols[kMasterRootBuf]);
        table.keyTypeCode = static_cast<int32_t>(numCols[kMasterKeyType]);
        table.indexedColumn = static_cast<int32_t>(numCols[kMasterIndexCol]);
        if (table.indexedColumn == 0x7fffffff) {
            table.indexedColumn = -1;
        }
        table.maxKey = numCols[kMasterMaxKey];
        table.recordCount = numCols[kMasterRecCount];

        // field types: plain type bytes until the -1 extension indicator, then
        // extension blocks: extType(1) + data; ext type 1 = sparse column
        // list (byte indexes terminated by -1 or end of data).
        const std::vector<uint8_t>& ft = binCols[kMasterFieldTypes];
        size_t i = 0;
        for (; i < ft.size(); i++) {
            int32_t b = static_cast<int8_t>(ft[i]);
            if (b == kFieldExtensionIndicator) {
                break;
            }
            table.fieldTypes.push_back(static_cast<GbfFieldType>(b));
        }
        bool parsingSparse = false;
        for (; i < ft.size(); i++) {
            int32_t b = static_cast<int8_t>(ft[i]);
            if (parsingSparse) {
                if (b == kFieldExtensionIndicator) {
                    parsingSparse = false;
                    continue;
                }
                if (b >= 0 && static_cast<size_t>(b) < table.fieldTypes.size()) {
                    table.sparseColumns.push_back(b);
                }
                continue;
            }
            if (b == kSparseFieldListExtension) {
                parsingSparse = true;
            }
        }

        // field names: ';' separated (Ghidra joins names with ';'); fall back
        // to ',' for older/malformed schema strings. Empty tokens (e.g. from a
        // trailing separator) are dropped. The name list may repeat an entry
        // per table version.
        const std::string& names = strCols[kMasterFieldNames];
        char sep = names.find(';') != std::string::npos ? ';' : ',';
        size_t start = 0;
        for (;;) {
            size_t comma = names.find(sep, start);
            std::string tok = (comma == std::string::npos) ? names.substr(start)
                : names.substr(start, comma - start);
            if (!tok.empty()) {
                table.fieldNames.push_back(tok);
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }

        tables_.push_back(std::move(table));
    });
}

void GbfReader::collectRecords(const GbfTableSchema& table,
    const std::function<void(const GbfRecord&)>& fn) const {
    if (table.rootBufferId < 0) {
        return;
    }
    const int32_t keySize = table.keySize();
    const int32_t recSize = table.fixedRecordSize();

    std::function<void(int32_t)> walk = [&](int32_t bid) {
        const std::vector<uint8_t>& b = block(bid);
        if (b.empty()) {
            return;
        }
        uint8_t nt = b[0];
        size_t n = b.size();

        auto emit = [&](std::vector<uint8_t> key, std::vector<uint8_t> data) {
            GbfRecord rec;
            rec.key = std::move(key);
            rec.data = std::move(data);
            rec.sparseFields = splitSparse(rec.data, table);
            fn(rec);
        };

        switch (static_cast<GbfNodeType>(nt)) {
            case GbfNodeType::LongKeyInterior: {
                int32_t kc = beI32(&b[1]);
                for (int i = 0; i < kc; i++) {
                    size_t off = 5 + static_cast<size_t>(i) * 12;
                    walk(beI32(&b[off + 8]));
                }
                break;
            }
            case GbfNodeType::LongKeyVarRec: {
                int32_t kc = beI32(&b[1]);
                for (int i = 0; i < kc; i++) {
                    size_t off = 13 + static_cast<size_t>(i) * 13;
                    std::vector<uint8_t> key(b.begin() + off, b.begin() + off + 8);
                    int32_t roff = beI32(&b[off + 8]);
                    uint8_t ind = b[off + 12];
                    if (ind != 0) {
                        if (roff + 4 > static_cast<int32_t>(n)) {
                            throw std::runtime_error("Gbf: chained record offset out of bounds");
                        }
                        int32_t cbId = beI32(&b[roff]);
                        emit(std::move(key), readChainedBuffer(cbId));
                    } else {
                        if (roff < 0 || static_cast<size_t>(roff) > n) {
                            throw std::runtime_error("Gbf: record offset out of bounds (block " + std::to_string(bid) + ", roff=" + std::to_string(roff) + ", n=" + std::to_string(n) + ")");
                        }
                        emit(std::move(key), std::vector<uint8_t>(b.begin() + roff, b.end()));
                    }
                }
                break;
            }
            case GbfNodeType::LongKeyFixedRec: {
                if (recSize < 0) {
                    throw std::runtime_error("Gbf: fixed-rec node with variable records");
                }
                int32_t kc = beI32(&b[1]);
                size_t entrySize = 8 + static_cast<size_t>(recSize);
                for (int i = 0; i < kc; i++) {
                    size_t off = 13 + static_cast<size_t>(i) * entrySize;
                    if (off + entrySize > n) {
                        throw std::runtime_error("Gbf: fixed record entry out of bounds");
                    }
                    emit(std::vector<uint8_t>(b.begin() + off, b.begin() + off + 8),
                        std::vector<uint8_t>(b.begin() + off + 8, b.begin() + off + entrySize));
                }
                break;
            }
            case GbfNodeType::VarKeyInterior: {
                int32_t kc = beI32(&b[2]);
                for (int i = 0; i < kc; i++) {
                    size_t off = 6 + static_cast<size_t>(i) * 8;
                    walk(beI32(&b[off + 4]));
                }
                break;
            }
            case GbfNodeType::VarKeyRec: {
                int32_t kc = beI32(&b[2]);
                int32_t nodeKeyType =
                    b.size() > 1 ? static_cast<int32_t>(b[1]) : table.keyTypeCode;
                for (int i = 0; i < kc; i++) {
                    size_t off = 14 + static_cast<size_t>(i) * 5;
                    int32_t koff = beI32(&b[off]);
                    uint8_t ind = b[off + 4];
                    if (koff < 0 || static_cast<size_t>(koff) >= n) {
                        throw std::runtime_error("Gbf: varkey offset out of bounds");
                    }
                    size_t keyOff = static_cast<size_t>(koff);
                    size_t keyStart = keyOff;
                    advanceKeyBytes(nodeKeyType, b.data(), n, keyOff);
                    std::vector<uint8_t> key(b.begin() + keyStart, b.begin() + keyOff);
                    {
                        // For a string/binary first component the stored key
                        // span starts with the 4-byte length prefix; strip it
                        // so keys compare by content.
                        int32_t first = nodeKeyType & 0x0F;
                        if (first == static_cast<int32_t>(GbfFieldType::String) ||
                            first == static_cast<int32_t>(GbfFieldType::Binary)) {
                            size_t contentStart = keyStart + 4;
                            if (contentStart <= keyOff) {
                                key.assign(b.begin() + contentStart, b.begin() + keyOff);
                            }
                        }
                    }
                    size_t recStart = keyOff;
                    if (recStart > n) {
                        throw std::runtime_error("Gbf: varkey record start out of bounds");
                    }
                    if (ind != 0) {
                        if (recStart + 4 > n) {
                            throw std::runtime_error("Gbf: chained record offset out of bounds");
                        }
                        int32_t cbId = beI32(&b[recStart]);
                        emit(std::move(key), readChainedBuffer(cbId));
                    } else {
                        emit(std::move(key),
                            std::vector<uint8_t>(b.begin() + static_cast<size_t>(recStart), b.end()));
                    }
                }
                break;
            }
            case GbfNodeType::FixedKeyInterior: {
                if (keySize < 0) {
                    throw std::runtime_error("Gbf: fixed-key interior with variable keys");
                }
                int32_t kc = beI32(&b[1]);
                size_t entrySize = static_cast<size_t>(keySize) + 4;
                for (int i = 0; i < kc; i++) {
                    size_t off = 5 + static_cast<size_t>(i) * entrySize;
                    walk(beI32(&b[off + static_cast<size_t>(keySize)]));
                }
                break;
            }
            case GbfNodeType::FixedKeyVarRec: {
                if (keySize < 0) {
                    throw std::runtime_error("Gbf: fixed-key varrec with variable keys");
                }
                int32_t kc = beI32(&b[1]);
                size_t entrySize = static_cast<size_t>(keySize) + 5;
                for (int i = 0; i < kc; i++) {
                    size_t off = 13 + static_cast<size_t>(i) * entrySize;
                    if (off + entrySize > n) {
                        throw std::runtime_error("Gbf: fixed-key varrec entry out of bounds");
                    }
                    std::vector<uint8_t> key(b.begin() + off, b.begin() + off + keySize);
                    int32_t roff = beI32(&b[off + static_cast<size_t>(keySize)]);
                    uint8_t ind = b[off + static_cast<size_t>(keySize) + 4];
                    if (ind != 0) {
                        if (roff + 4 > static_cast<int32_t>(n)) {
                            throw std::runtime_error("Gbf: chained record offset out of bounds");
                        }
                        int32_t cbId = beI32(&b[roff]);
                        emit(std::move(key), readChainedBuffer(cbId));
                    } else {
                        if (roff < 0 || static_cast<size_t>(roff) >= n) {
                            throw std::runtime_error("Gbf: record offset out of bounds (block " + std::to_string(bid) + ", roff=" + std::to_string(roff) + ", n=" + std::to_string(n) + ")");
                        }
                        emit(std::move(key), std::vector<uint8_t>(b.begin() + roff, b.end()));
                    }
                }
                break;
            }
            case GbfNodeType::FixedKeyFixedRec: {
                if (keySize < 0 || recSize < 0) {
                    throw std::runtime_error("Gbf: fixed-key fixed-rec with variable format");
                }
                int32_t kc = beI32(&b[1]);
                size_t entrySize = static_cast<size_t>(keySize) + static_cast<size_t>(recSize);
                for (int i = 0; i < kc; i++) {
                    size_t off = 13 + static_cast<size_t>(i) * entrySize;
                    if (off + entrySize > n) {
                        throw std::runtime_error("Gbf: fixed-key fixed-rec entry out of bounds");
                    }
                    std::vector<uint8_t> key(b.begin() + off, b.begin() + off + keySize);
                    std::vector<uint8_t> data(b.begin() + off + keySize, b.begin() + off + entrySize);
                    emit(std::move(key), std::move(data));
                }
                break;
            }
            default:
                throw std::runtime_error("Gbf: unexpected node type " + std::to_string(nt) +
                    " in table " + table.name);
        }
    };
    walk(table.rootBufferId);
}

void GbfReader::visitRecords(const GbfTableSchema& table,
    const std::function<void(const GbfRecord&)>& fn) const {
    collectRecords(table, fn);
}

}  // namespace ghidra