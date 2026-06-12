#include <ghidra/PdbParser.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/UnsignedLongLongDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DoubleDataType.h>
#include <ghidra/CharDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/Undefined4DataType.h>
#include <ghidra/TypedefDataType.h>
#include <fstream>
#include <cstring>
#include <algorithm>

namespace ghidra {
namespace pdb {

// ================================================================
// PdbFile — MSF container reader
// ================================================================

static uint32_t read32le(const uint8_t* p) { return p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24); }

bool PdbFile::open(const std::string& path) {
    path_ = path;
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    size_t sz = static_cast<size_t>(in.tellg()); in.seekg(0);
    fileBuf_.resize(sz);
    if (!in.read(reinterpret_cast<char*>(fileBuf_.data()), static_cast<std::streamsize>(sz))) return false;

    const uint8_t* data = fileBuf_.data();
    if (sz < 64) return false;
    const char* magic = "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\0\0\0";
    if (memcmp(data, magic, 32) != 0) return false;

    hdr_.blockSize = read32le(data+32);
    hdr_.numBlocks = read32le(data+40);
    hdr_.numDirBytes = read32le(data+44);
    hdr_.blockMapAddr = read32le(data+52);
    if (hdr_.blockSize == 0 || hdr_.numBlocks == 0) return false;

    good_ = readStreamDirectory();
    return good_;
}

bool PdbFile::readStreamDirectory() {
    uint32_t blockSize = hdr_.blockSize;
    const uint8_t* data = fileBuf_.data();
    size_t fileSize = fileBuf_.size();

    // Read directory block list
    uint32_t numDirBlocks = (hdr_.numDirBytes + blockSize - 1) / blockSize;
    std::vector<uint32_t> dirBlocks;
    uint32_t bma = hdr_.blockMapAddr;
    if (bma == 0 || bma >= hdr_.numBlocks) return false;
    dirBlocks.push_back(bma);

    uint32_t blockOff = bma * blockSize;
    while (dirBlocks.size() < numDirBlocks && blockOff + 4 <= fileSize) {
        uint32_t nextBlock = read32le(data + blockOff);
        if (nextBlock == 0 || nextBlock == 0xFFFFFFFF || nextBlock >= hdr_.numBlocks) break;
        dirBlocks.push_back(nextBlock);
        blockOff = nextBlock * blockSize;
    }
    if (dirBlocks.size() < numDirBlocks) return false;

    // Read directory data
    std::vector<uint8_t> dirData(hdr_.numDirBytes);
    for (uint32_t i = 0; i < numDirBlocks; ++i) {
        uint32_t off = dirBlocks[i] * blockSize;
        size_t copySz = std::min<size_t>(blockSize, dirData.size() - i * blockSize);
        if (off + copySz > fileSize) return false;
        memcpy(dirData.data() + i * blockSize, data + off, copySz);
    }

    uint32_t numStreams = read32le(dirData.data());
    streamSizes_.reserve(numStreams);
    uint32_t pos = 4;
    for (uint32_t i = 0; i < numStreams; ++i) {
        if (pos + 4 > dirData.size()) return false;
        streamSizes_.push_back(read32le(dirData.data()+pos)); pos += 4;
    }

    streamBlockLists_.resize(numStreams);
    for (uint32_t i = 0; i < numStreams; ++i) {
        uint32_t sz = streamSizes_[i];
        if (sz == 0 || sz == 0xFFFFFFFF) continue;
        uint32_t numBlocks = (sz + blockSize - 1) / blockSize;
        for (uint32_t j = 0; j < numBlocks; ++j) {
            if (pos + 4 > dirData.size()) return false;
            streamBlockLists_[i].push_back(read32le(dirData.data()+pos)); pos += 4;
        }
    }
    return true;
}

uint32_t PdbFile::getStreamSize(uint32_t idx) {
    return (idx < streamSizes_.size()) ? streamSizes_[idx] : 0;
}

bool PdbFile::getStream(uint32_t idx, std::vector<uint8_t>& out) {
    if (idx >= streamSizes_.size()) return false;
    uint32_t sz = streamSizes_[idx];
    if (sz == 0 || sz == 0xFFFFFFFF) return false;
    out.resize(sz);
    uint32_t bs = hdr_.blockSize;
    const uint8_t* data = fileBuf_.data();
    size_t fileSize = fileBuf_.size();
    for (uint32_t i = 0; i < streamBlockLists_[idx].size(); ++i) {
        uint32_t b = streamBlockLists_[idx][i];
        uint32_t off = b * bs;
        size_t copySz = std::min<uint32_t>(bs, sz - i * bs);
        if (off + copySz > fileSize) return false;
        memcpy(out.data() + i * bs, data + off, copySz);
    }
    return true;
}

// ================================================================
// PdbTypeReader — TPI type records
// ================================================================

static const uint32_t LF_PROCEDURE = 0x1008;
static const uint32_t LF_ARGLIST   = 0x1201;
static const uint32_t LF_POINTER   = 0x1002;
static const uint32_t LF_STRUCTURE = 0x1505;
static const uint32_t LF_UNION     = 0x1506;
static const uint32_t LF_ENUM      = 0x1507;
static const uint32_t LF_ARRAY     = 0x1503;
static const uint32_t LF_MODIFIER  = 0x1001;
static const uint32_t LF_MFUNCTION = 0x1009;
static const uint32_t LF_METHODLIST= 0x1206;

bool PdbTypeReader::parseRecords(const uint8_t* data, uint32_t size) {
    uint32_t pos = 0;
    while (pos + 4 <= size) {
        uint16_t len = data[pos] | (data[pos+1] << 8);
        uint16_t ty = data[pos+2] | (data[pos+3] << 8);
        if (len < 2) break;
        uint32_t recSize = len + 2;
        uint32_t recOff = pos + 2;
        if (recOff + len > size) break;

        uint32_t typeIdx = (recOff - 2) / 4; // approximate index from offset
        // Real TPI uses specific index numbering; we use offset/4 as key
        uint32_t key = recOff;

        PdbType pt;
        const uint8_t* rec = data + recOff;

        switch (ty) {
            case LF_PROCEDURE: // return_type(4), call_conv(1), flags(1), param_count(2), arg_list(4)
                if (len >= 12) {
                    pt.kind = PdbType::PROCEDURE;
                    pt.returnTypeId = read32le(rec);
                    pt.callConv = rec[4];
                    pt.argListId = read32le(rec + 8);
                }
                break;
            case LF_MFUNCTION: // return_type(4), class_type(4), this_type(4), call_conv(1), flags(1), param_count(2), arg_list(4), this_adjust(4)
                if (len >= 22) {
                    pt.kind = PdbType::PROCEDURE;
                    pt.returnTypeId = read32le(rec);
                    pt.callConv = rec[12];
                    pt.argListId = read32le(rec + 16);
                }
                break;
            case LF_ARGLIST: { // count(4), type_indices[]
                uint32_t count = read32le(rec);
                if (len >= 4 + count * 4) {
                    pt.kind = PdbType::ARGLIST;
                    for (uint32_t i = 0; i < count; ++i)
                        pt.memberTypeIds.push_back(read32le(rec + 4 + i*4));
                }
                break;
            }
            case LF_POINTER: { // pointee(4), ptrtype(4), ptrsize specific from upper nibble
                uint32_t pointee = read32le(rec);
                uint32_t attr = read32le(rec+4);
                pt.kind = PdbType::POINTER;
                pt.pointeeId = pointee;
                pt.ptrSize = (attr >> 13) & 0x7F;
                if (pt.ptrSize == 0) pt.ptrSize = 8;
                break;
            }
            case LF_ARRAY: // element_type(4), index_type(4), size(var)
                if (len >= 8) {
                    pt.kind = PdbType::ARRAY;
                    pt.elementTypeId = read32le(rec);
                    if (len >= 10) {
                        uint16_t szLo = rec[8] | (rec[9]<<8);
                        uint64_t sz = szLo;
                        if (len >= 12 && szLo == 0xFFFF) sz = read32le(rec+8) | ((uint64_t)read32le(rec+12)<<32);
                        pt.size = static_cast<uint64_t>(sz);
                    }
                }
                break;
            case LF_STRUCTURE: case LF_UNION: case LF_ENUM:
                if (len >= 22) {
                    pt.kind = (ty == LF_STRUCTURE) ? PdbType::STRUCT :
                              (ty == LF_UNION) ? PdbType::UNION : PdbType::ENUM;
                    pt.size = read32le(rec+16) | ((uint64_t)read32le(rec+18)<<32);
                    // Name at offset 22... variable length
                    uint16_t nameOff = rec[20] | (rec[21]<<8);
                    if (nameOff + recOff + 2 < pos + len) {
                        pt.udtName = reinterpret_cast<const char*>(data + recOff + nameOff);
                    }
                }
                break;
            case LF_MODIFIER: // modified_type(4), modifiers(2)
                if (len >= 6) {
                    pt.kind = PdbType::MODIFIER;
                    pt.baseTypeId = read32le(rec);
                }
                break;
            default: pt.kind = PdbType::UNKNOWN; break;
        }

        types_[key] = pt;
        pos += ((recSize + 3) / 4) * 4; // dword align
    }
    return true;
}

bool PdbTypeReader::parseTpi(PdbFile& pdb, uint32_t tpiStreamIdx) {
    std::vector<uint8_t> data;
    if (!pdb.getStream(tpiStreamIdx, data) || data.size() < 56) return false;
    const uint8_t* d = data.data();
    uint32_t headerSize = read32le(d+4);
    uint32_t typeRecordBytes = read32le(d+20);
    if (headerSize < 56 || headerSize + typeRecordBytes > data.size()) return false;
    return parseRecords(d + headerSize, typeRecordBytes);
}

bool PdbTypeReader::parseIpi(PdbFile& pdb, uint32_t ipiStreamIdx) {
    std::vector<uint8_t> data;
    if (!pdb.getStream(ipiStreamIdx, data) || data.size() < 56) return false;
    const uint8_t* d = data.data();
    uint32_t headerSize = read32le(d+4);
    uint32_t typeRecordBytes = read32le(d+20);
    if (headerSize + typeRecordBytes > data.size()) return false;
    return parseRecords(d + headerSize, typeRecordBytes);
}

const PdbType* PdbTypeReader::getType(uint32_t idx) const {
    auto it = types_.find(idx);
    return (it != types_.end()) ? &it->second : nullptr;
}

DataType* PdbTypeReader::resolveType(uint32_t idx, DataTypeManager* dtm,
                                      std::unordered_map<uint32_t, DataType*>& cache) const {
    if (idx == 0) return dtm->getDataType(CategoryPath::ROOT(), "void");
    auto cacheIt = cache.find(idx);
    if (cacheIt != cache.end()) return cacheIt->second;

    DataType* result = nullptr;
    auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtm);

    // Simple types: T_* (< 0x1000)
    if (idx < 0x1000) {
        switch (idx) {
            case 0x0003: result = dtm->getDataType(CategoryPath::ROOT(), "void"); break;
            case 0x0074: result = dtm->getDataType(CategoryPath::ROOT(), "int"); break;   // T_INT4
            case 0x0075: result = dtm->getDataType(CategoryPath::ROOT(), "dword"); break; // T_UINT4
            case 0x0010: result = dtm->getDataType(CategoryPath::ROOT(), "byte"); break;  // T_CHAR
            case 0x0020: result = dtm->getDataType(CategoryPath::ROOT(), "byte"); break;  // T_UCHAR
            case 0x0012: result = dtm->getDataType(CategoryPath::ROOT(), "short"); break; // T_SHORT
            case 0x0022: result = dtm->getDataType(CategoryPath::ROOT(), "word"); break;  // T_USHORT
            case 0x0076: result = dtm->getDataType(CategoryPath::ROOT(), "long"); break;  // T_LONG
            case 0x0077: result = dtm->getDataType(CategoryPath::ROOT(), "qword"); break; // T_ULONG
            case 0x0013: result = dtm->getDataType(CategoryPath::ROOT(), "qword"); break; // T_QUAD (int64)
            case 0x0023: result = dtm->getDataType(CategoryPath::ROOT(), "qword"); break; // T_UQUAD
            case 0x0040: result = dtm->getDataType(CategoryPath::ROOT(), "float"); break;
            case 0x0041: result = dtm->getDataType(CategoryPath::ROOT(), "double"); break;
            case 0x0030: result = dtm->getDataType(CategoryPath::ROOT(), "bool"); break;
            case 0x000C: result = dtm->getDataType(CategoryPath::ROOT(), "byte"); break;  // T_UCHAR
            case 0x0070: result = dtm->getDataType(CategoryPath::ROOT(), "byte"); break;  // T_1BYTE
            case 0x0071: result = dtm->getDataType(CategoryPath::ROOT(), "word"); break;  // T_2BYTE
            case 0x0072: result = dtm->getDataType(CategoryPath::ROOT(), "word"); break;  // T_2BYTE unsigned -> word
            default: result = dtm->getDataType(CategoryPath::ROOT(), "byte"); break;
        }
        if (result) cache[idx] = result;
        return result;
    }

    auto* type = getType(idx);
    if (!type) return dtm->getDataType(CategoryPath::ROOT(), "byte");

    switch (type->kind) {
        case PdbType::POINTER: {
            DataType* target = resolveType(type->pointeeId, dtm, cache);
            if (!target) target = dtm->getDataType(CategoryPath::ROOT(), "void");
            int ptrSz = static_cast<int>(type->ptrSize);
            if (ptrSz == 0) ptrSz = 8;
            if (dtmImpl) {
                result = new PointerDataType(target, ptrSz, dtmImpl);
                dtmImpl->addDataType(result);
            }
            break;
        }
        case PdbType::PROCEDURE: {
            // Function type: return type is what we need for function signatures
            result = resolveType(type->returnTypeId, dtm, cache);
            break;
        }
        case PdbType::MODIFIER: {
            result = resolveType(type->baseTypeId, dtm, cache);
            break;
        }
        case PdbType::STRUCT: case PdbType::UNION: case PdbType::ENUM: {
            if (!type->udtName.empty() && dtmImpl) {
                auto* existing = dtm->getDataType(CategoryPath::ROOT(), type->udtName);
                if (existing) { result = existing; break; }
                if (type->kind == PdbType::STRUCT) {
                    auto* st = new StructureDataType(CategoryPath::ROOT(), type->udtName, 0, dtmImpl);
                    dtmImpl->addDataType(st);
                    result = st;
                } else if (type->kind == PdbType::UNION) {
                    auto* un = new UnionDataType(CategoryPath::ROOT(), type->udtName, dtmImpl);
                    dtmImpl->addDataType(un);
                    result = un;
                } else {
                    auto* en = new EnumDataType(CategoryPath::ROOT(), type->udtName, static_cast<int>(type->size), dtmImpl);
                    dtmImpl->addDataType(en);
                    result = en;
                }
            }
            break;
        }
        case PdbType::ARRAY: {
            DataType* elem = resolveType(type->elementTypeId, dtm, cache);
            if (elem && dtmImpl) {
                result = new ArrayDataType(elem, static_cast<int>(type->size / (elem->getLength() > 0 ? elem->getLength() : 1)), -1, dtmImpl);
                dtmImpl->addDataType(result);
            }
            break;
        }
        default: break;
    }

    if (!result) result = dtm->getDataType(CategoryPath::ROOT(), "byte");
    cache[idx] = result;
    return result;
}

// ================================================================
// PdbDbiReader — DBI stream parser
// ================================================================

bool PdbDbiReader::parse(PdbFile& pdb, DbiInfo& info, std::map<uint32_t, uint64_t>& sectionBases) {
    std::vector<uint8_t> data;
    // DBI is stream 3
    if (!pdb.getStream(3, data) || data.size() < 64) return false;
    const uint8_t* d = data.data();

    int32_t sig = static_cast<int32_t>(read32le(d));
    if (sig != -1) return false;
    info.globalStreamIdx = read32le(d+12);
    info.publicStreamIdx = read32le(d+16);
    info.symRecordStreamIdx = read32le(d+20);
    uint32_t moduleSize = read32le(d+24);

    // Section contribution: determines section→VA mapping
    uint16_t sectionContribVersion = d[32] | (d[33]<<8);
    if (sectionContribVersion == 0x0012) {
        uint32_t scOffset = read32le(d+44);
        uint32_t scSize = read32le(d+48);
        if (scOffset + scSize <= data.size()) {
            const uint8_t* sc = data.data() + scOffset;
            uint32_t scPos = 0;
            while (scPos + 40 <= scSize) {
                uint32_t section = read32le(sc+scPos+16);
                uint32_t rva = read32le(sc+scPos+24);
                if (sectionBases.find(section) == sectionBases.end())
                    sectionBases[section] = rva;
                scPos += 40;
            }
        }
    }

    info.parsed = true;
    return true;
}

// ================================================================
// PdbSymbolReader — symbol records
// ================================================================

static const uint16_t S_GPROC32  = 0x1110;
static const uint16_t S_LPROC32  = 0x1112;
static const uint16_t S_PUB32    = 0x110E;
static const uint16_t S_GDATA32  = 0x110D;
static const uint16_t S_LDATA32  = 0x110C;
static const uint16_t S_END      = 0x0006;

uint64_t PdbSymbolReader::sectionToVA(uint32_t seg, uint64_t off) const {
    auto it = sectionBases_.find(seg);
    if (it != sectionBases_.end()) return it->second + off;
    return off;
}

static std::string readPascalString(const uint8_t* data, uint32_t& pos, uint32_t maxPos) {
    if (pos >= maxPos) return "";
    uint16_t len = data[pos] | (data[pos+1]<<8); pos += 2;
    if (pos + len > maxPos) return "";
    std::string s(reinterpret_cast<const char*>(data + pos), len);
    pos += len;
    return s;
}

static bool parseSymbolStream(const uint8_t* data, uint32_t size, uint64_t sectionBase,
                               std::vector<PdbSymbol>& functions, std::vector<PdbSymbol>& globals) {
    uint32_t pos = 0;
    while (pos + 4 <= size) {
        uint16_t len  = data[pos] | (data[pos+1]<<8);
        uint16_t type = data[pos+2] | (data[pos+3]<<8);
        if (len < 2) break;
        uint32_t recEnd = pos + len + 2;
        if (recEnd > size) break;

        const uint8_t* rec = data + pos + 4;
        uint32_t recSize = len - 2;

        switch (type) {
            case S_GPROC32: case S_LPROC32: {
                if (recSize >= 37) {
                    PdbSymbol s; s.type = type;
                    s.typeIndex = read32le(rec+24);
                    s.offset = read32le(rec+28);
                    s.segment = rec[32] | (rec[33]<<8);
                    uint32_t np = pos + 4 + 35; // skip fixed fields to Pascal string
                    s.name = readPascalString(data, np, recEnd);
                    functions.push_back(s);
                }
                break;
            }
            case S_PUB32: {
                if (recSize >= 12) {
                    PdbSymbol s; s.type = type;
                    s.offset = read32le(rec+4);
                    s.segment = rec[8] | (rec[9]<<8);
                    uint32_t np = pos + 4 + 10; // skip flags+off+seg to Pascal string
                    s.name = readPascalString(data, np, recEnd);
                    globals.push_back(s);
                }
                break;
            }
            case S_GDATA32: case S_LDATA32: break;
            case S_END: break;
            default: break;
        }
        pos = recEnd;
    }
    return true;
}

bool PdbSymbolReader::parseGlobalSymbols(PdbFile& pdb, uint32_t streamIdx) {
    std::vector<uint8_t> data;
    if (!pdb.getStream(streamIdx, data)) return false;
    return parseSymbolStream(data.data(), static_cast<uint32_t>(data.size()), 0, functions_, globals_);
}

bool PdbSymbolReader::parseModuleSymbols(PdbFile& pdb, const std::vector<uint8_t>& modStream, uint64_t sectionBase) {
    return parseSymbolStream(modStream.data(), static_cast<uint32_t>(modStream.size()), sectionBase, functions_, globals_);
}

} // namespace pdb
} // namespace ghidra
