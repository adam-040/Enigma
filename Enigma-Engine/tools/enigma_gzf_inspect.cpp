/* ###
 * IP: Enigma Engine (original work)
 *
 * Inspects Ghidra project database files: opens a .gbf database directly, a
 * .rep project directory, or a .gzf export archive and prints the table
 * inventory (master table) and optionally decoded records.
 *
 * Usage:
 *   enigma_gzf_inspect <db.gbf | dir.rep | file.gzf> [options]
 *     --list             print program list when source is a project (default)
 *     --table NAME       dump records of one table
 *     --limit N          max records printed per table (default 5)
 *     --all              dump records of every table
 *     --program NAME     restrict to a named program (project sources only)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/import/GbfReader.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <memory>
#include <map>
#include <string>
#include <vector>

#include <ghidra/import/RepProject.h>

namespace {

using namespace ghidra;

constexpr int kDefaultLimit = 5;

std::string keyToString(const GbfTableSchema& table, const std::vector<uint8_t>& key);

// Recover the original file from the "File Bytes" table (same decode as
// GzfProgramImporter::importFileBytes).  Returns false when the table is
// missing or unreadable.
bool extractFileBytes(const GbfReader& gbf, std::string& name, std::vector<uint8_t>& out) {
    const GbfTableSchema* t = gbf.findTable("File Bytes");
    if (!t) {
        return false;
    }
    bool found = false;
    gbf.visitRecords(*t, [&](const GbfRecord& rec) {
        if (found) {
            return;
        }
        const std::vector<uint8_t>& d = rec.data;
        size_t off = 0;
        auto beNum = [&](size_t n) {
            int64_t v = 0;
            for (size_t i = 0; i < n && off < d.size(); ++i) {
                v = (v << 8) | d[off++];
            }
            return v;
        };
        auto beStr = [&]() {
            int32_t len = static_cast<int32_t>(beNum(4));
            if (len < 0 || off + static_cast<size_t>(len) > d.size()) {
                return std::string();
            }
            std::string s(reinterpret_cast<const char*>(d.data() + off),
                          static_cast<size_t>(len));
            off += static_cast<size_t>(len);
            return s;
        };
        auto beBin = [&]() {
            int32_t len = static_cast<int32_t>(beNum(4));
            if (len < 0 || off + static_cast<size_t>(len) > d.size()) {
                return std::vector<uint8_t>();
            }
            std::vector<uint8_t> b(d.begin() + static_cast<ptrdiff_t>(off),
                                   d.begin() + static_cast<ptrdiff_t>(off + len));
            off += static_cast<size_t>(len);
            return b;
        };
        name = beStr();
        beNum(8);  // Offset
        int64_t fileSize = beNum(8);  // Size
        std::vector<uint8_t> bufferIds = beBin();
        if (bufferIds.empty()) {
            return;
        }
        int64_t chainId = 0;
        const size_t n = bufferIds.size();
        for (size_t i = n > 4 ? n - 4 : 0; i < n; ++i) {
            chainId = (chainId << 8) | bufferIds[i];
        }
        std::vector<uint8_t> bytes =
            gbf.readChainedBuffer(static_cast<int32_t>(chainId));
        if (fileSize > 0 && bytes.size() >= static_cast<size_t>(fileSize)) {
            bytes.resize(static_cast<size_t>(fileSize));
        }
        if (!bytes.empty()) {
            out = std::move(bytes);
            found = true;
        }
    });
    return found;
}

int64_t keyToLongV(const GbfTableSchema& table, const std::vector<uint8_t>& key) {
    if (key.size() == 8) {
        uint64_t v = 0;
        for (uint8_t b : key) {
            v = (v << 8) | b;
        }
        return static_cast<int64_t>(v);
    }
    char* end = nullptr;
    return std::strtoll(keyToString(table, key).c_str(), &end, 10);
}

std::string keyToString(const GbfTableSchema& table, const std::vector<uint8_t>& key) {
    int32_t ks = table.keySize();
    if (ks == 8) {
        char buf[32];
        int64_t v = static_cast<int64_t>((static_cast<uint64_t>(key[0]) << 56) |
            (static_cast<uint64_t>(key[1]) << 48) | (static_cast<uint64_t>(key[2]) << 40) |
            (static_cast<uint64_t>(key[3]) << 32) | (static_cast<uint64_t>(key[4]) << 24) |
            (static_cast<uint64_t>(key[5]) << 16) | (static_cast<uint64_t>(key[6]) << 8) |
            static_cast<uint64_t>(key[7]));
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
        return buf;
    }
    if (ks == 4 && key.size() == 4) {
        uint32_t v = (static_cast<uint32_t>(key[0]) << 24) | (static_cast<uint32_t>(key[1]) << 16) |
            (static_cast<uint32_t>(key[2]) << 8) | key[3];
        return std::to_string(v);
    }
    std::string out = "0x";
    static const char* kHex = "0123456789abcdef";
    for (uint8_t b : key) {
        out += kHex[b >> 4];
        out += kHex[b & 0xF];
    }
    return out;
}

std::string fieldTypeName(GbfFieldType t) {
    switch (t) {
        case GbfFieldType::Byte: return "byte";
        case GbfFieldType::Short: return "short";
        case GbfFieldType::Int: return "int";
        case GbfFieldType::Long: return "long";
        case GbfFieldType::String: return "string";
        case GbfFieldType::Binary: return "bytes";
        case GbfFieldType::Bool: return "bool";
        case GbfFieldType::Fixed10: return "fixed10";
    }
    return "?";
}

void printRecord(const GbfTableSchema& table, const GbfRecord& rec, bool showKey) {
    // fieldNames includes the key field name(s) first; fieldTypes covers the
    // data fields only. Pair data field c with names[c + keyNames].
    const size_t keyNames = table.fieldNames.size() > table.fieldTypes.size()
        ? table.fieldNames.size() - table.fieldTypes.size() : 0;
    std::string line;
    if (showKey) {
        line += "key=" + keyToString(table, rec.key) + " ";
    }
    size_t off = 0;
    const uint8_t* p = rec.data.data();
    size_t sz = rec.data.size();
    for (size_t c = 0; c < table.fieldTypes.size(); c++) {
        if (std::find(table.sparseColumns.begin(), table.sparseColumns.end(),
                static_cast<int32_t>(c)) != table.sparseColumns.end()) {
            continue;
        }
        std::string name = c + keyNames < table.fieldNames.size()
            ? table.fieldNames[c + keyNames] : "col";
        GbfFieldType t = table.fieldTypes[c];
        std::string value;
        try {
            off = GbfReader::formatField(t, p, sz, off, value);
        } catch (const std::exception& e) {
            value = "<" + std::string(e.what()) + ">";
        }
        line += name + "=" + value + " ";
    }
    for (const auto& sf : rec.sparseFields) {
        int32_t c = sf.first;
        std::string name = static_cast<size_t>(c) < table.fieldNames.size()
            ? table.fieldNames[static_cast<size_t>(c)]
            : "col";
        GbfFieldType t = table.fieldTypes[static_cast<size_t>(c)];
        std::string value;
        try {
            value.clear();
            GbfReader::formatField(t, sf.second.data(), sf.second.size(), 0, value);
        } catch (const std::exception& e) {
            value = "<" + std::string(e.what()) + ">";
        }
        line += name + "=" + value + " ";
    }
    if (line.size() > 400) {
        line.resize(400);
        line += " ...";
    }
    std::cout << "  " << line << "\n";
}

void printInventory(const GbfReader& gbf) {
    std::cout << "fileId: 0x" << std::hex << gbf.fileId() << std::dec
              << "  headerVersion: " << gbf.headerVersion()
              << "  blockSize: " << gbf.blockSize()
              << "  firstFreeId: " << gbf.firstFreeBufferId() << "\n";
    std::cout << "DBParms:";
    for (const auto& p : gbf.parameters()) {
        std::cout << " " << p.first << "=" << p.second;
    }
    std::cout << "\n";
    std::cout << "tables: " << gbf.tables().size() << "\n";
    std::cout << std::setw(38) << std::left << "TABLE"
              << std::setw(5) << std::right << "VER"
              << std::setw(7) << "ROOT"
              << std::setw(7) << "IDXCOL"
              << std::setw(11) << "RECS"
              << " | key type / columns\n";
    for (const GbfTableSchema& t : gbf.tables()) {
        std::cout << std::setw(38) << std::left << t.name
                  << std::setw(5) << std::right << t.version
                  << std::setw(7) << t.rootBufferId
                  << std::setw(7) << t.indexedColumn
                  << std::setw(11) << t.recordCount
                  << " | key=";
        if (t.isIndexTable()) {
            std::cout << "idx(" << (t.keyTypeCode & 0xF) << "<<" << 4 << "|"
                      << ((t.keyTypeCode >> 4) & 0xF) << ")";
        } else {
            std::cout << (t.keyTypeCode & 0xF);
        }
        std::cout << " [";
        for (size_t c = 0; c < t.fieldTypes.size(); c++) {
            if (c) {
                std::cout << ",";
            }
            std::cout << fieldTypeName(t.fieldTypes[c]);
            if (std::find(t.sparseColumns.begin(), t.sparseColumns.end(), static_cast<int32_t>(c)) !=
                t.sparseColumns.end()) {
                std::cout << "?";
            }
        }
        std::cout << "]\n";
        if (!t.fieldNames.empty()) {
            std::cout << std::setw(92) << std::right << " " << "  ";
            for (size_t c = 0; c < t.fieldNames.size(); c++) {
                if (c) {
                    std::cout << " ";
                }
                std::cout << t.fieldNames[c];
            }
            std::cout << "\n";
        }
    }
}

void dumpTable(const GbfReader& gbf, const GbfTableSchema& table, int limit) {
    std::cout << "table " << table.name << " (root " << table.rootBufferId << ", "
              << table.recordCount << " recs):\n";
    int count = 0;
    try {
        gbf.visitRecords(table, [&](const GbfRecord& rec) {
            if (limit >= 0 && count >= limit) {
                return;
            }
            printRecord(table, rec, true);
            count++;
        });
    } catch (const std::exception& e) {
        std::cout << "  ERROR: " << e.what() << "\n";
    }
    if (limit >= 0 && count >= limit && table.recordCount > static_cast<int64_t>(count)) {
        std::cout << "  ... (" << (table.recordCount - count) << " more)\n";
    }
}

// ---------------------------------------------------------------------------
// Reference-list decoding (ghidra.program.database.references.RefListV0):
//
//   record key            = address-map key of the "from" (FROM REFS) or
//                           "to" (TO REFS) address
//   col 0 (int)           = number of refs
//   col 1 (binary)        = concatenated per-ref records
//   col 2 (byte)          = ref level (TO REFS only)
//
//   per-ref layout: [8B BE addrKey][1B flags][1B refType][1B opIndex]
//                   [+8B symbolID if flags & 0x08]
//                   [+8B offsetOrShift if flags & (0x04|0x10)]
//   flags: 0x01|0x60 source-type split bits, 0x02 primary, 0x04 offset ref,
//          0x08 has symbol id, 0x10 shifted ref
// ---------------------------------------------------------------------------

struct DecodedRef {
    uint64_t addrKey = 0;          // counter-space address-map key
    uint8_t flags = 0;
    uint8_t type = 0;              // RefType value byte
    int8_t opIndex = 0;
    int64_t symbolID = -1;
    uint64_t offsetOrShift = 0;
    bool valid = false;
    std::string error;
};

DecodedRef decodeRef(const std::vector<uint8_t>& data, size_t& pos) {
    DecodedRef r;
    if (pos + 11 > data.size()) {
        r.error = "truncated ref header";
        return r;
    }
    auto be64 = [&](size_t off) {
        uint64_t v = 0;
        for (size_t i = 0; i < 8; ++i) {
            v = (v << 8) | data[off + i];
        }
        return v;
    };
    r.addrKey = be64(pos);
    pos += 8;
    r.flags = data[pos++];
    r.type = data[pos++];
    r.opIndex = static_cast<int8_t>(data[pos++]);
    if (r.flags & 0x08) {
        if (pos + 8 > data.size()) {
            r.error = "truncated symbol id";
            return r;
        }
        r.symbolID = static_cast<int64_t>(be64(pos));
        pos += 8;
    }
    if (r.flags & (0x04 | 0x10)) {
        if (pos + 8 > data.size()) {
            r.error = "truncated offset/shift";
            return r;
        }
        r.offsetOrShift = be64(pos);
        pos += 8;
    }
    r.valid = true;
    return r;
}

const char* refTypeName(uint8_t v) {
    switch (v) {
        case 0xFE: return "INVALID";
        case 0xFF: return "FLOW";
        case 0: return "FALL_THROUGH";
        case 1: return "UNCONDITIONAL_JUMP";
        case 2: return "CONDITIONAL_JUMP";
        case 3: return "UNCONDITIONAL_CALL";
        case 4: return "CONDITIONAL_CALL";
        case 5: return "TERMINATOR";
        case 6: return "COMPUTED_JUMP";
        case 7: return "CONDITIONAL_TERMINATOR";
        case 8: return "COMPUTED_CALL";
        case 9: return "INDIRECTION";
        case 10: return "CALL_TERMINATOR";
        case 11: return "JUMP_TERMINATOR";
        case 12: return "CONDITIONAL_COMPUTED_JUMP";
        case 13: return "CONDITIONAL_COMPUTED_CALL";
        case 14: return "CONDITIONAL_CALL_TERMINATOR";
        case 15: return "COMPUTED_CALL_TERMINATOR";
        case 16: return "CALL_OVERRIDE_UNCONDITIONAL";
        case 17: return "JUMP_OVERRIDE_UNCONDITIONAL";
        case 18: return "CALLOTHER_OVERRIDE_CALL";
        case 19: return "CALLOTHER_OVERRIDE_JUMP";
        case 100: return "DATA";
        case 101: return "READ";
        case 102: return "WRITE";
        case 103: return "READ_WRITE";
        case 104: return "READ_IND";
        case 105: return "WRITE_IND";
        case 106: return "READ_WRITE_IND";
        case 107: return "PARAM";
        case 113: return "EXTERNAL_REF";
        case 114: return "DATA_IND";
        case 127: return "THUNK";
    }
    return "?";
}

const char* refSourceName(uint8_t flags) {
    int id = static_cast<int>(((flags & 0x60) >> 4) | (flags & 0x01));
    switch (id) {
        case 0: return "DEFAULT";
        case 1: return "USER_DEFINED";
        case 2: return "ANALYSIS";
        case 3: return "IMPORTED";
        case 4: return "AI";
    }
    return "?";
}

std::string hexKey(uint64_t key) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(key));
    return buf;
}

void dumpRefsTable(const GbfReader& gbf, const GbfTableSchema& table, int limit) {
    const bool isFrom = table.name.find("FROM") != std::string::npos;
    std::cout << "table " << table.name << " (root " << table.rootBufferId << ", "
              << table.recordCount << " recs, " << (isFrom ? "from" : "to") << "-list):\n";
    int64_t totalRefs = 0;
    int64_t okRecords = 0;
    int64_t badRecords = 0;
    int64_t badRefs = 0;
    int64_t withSymbolId = 0;
    int64_t offsetOrShift = 0;
    std::map<uint8_t, int64_t> typeCounts;
    std::map<std::string, int64_t> sourceCounts;
    int count = 0;
    gbf.visitRecords(table, [&](const GbfRecord& rec) {
        if (rec.data.size() < 4) {
            badRecords++;
            return;
        }
        size_t off = 0;
        int32_t numRefs = 0;
        for (int i = 0; i < 4; ++i) {
            numRefs = (numRefs << 8) | rec.data[off++];
        }
        int32_t binLen = 0;
        for (int i = 0; i < 4; ++i) {
            binLen = (binLen << 8) | rec.data[off++];
        }
        if (binLen < 0 || static_cast<size_t>(binLen) > rec.data.size() - off) {
            badRecords++;
            return;
        }
        std::vector<uint8_t> bin(rec.data.begin() + static_cast<int64_t>(off),
                                 rec.data.begin() + static_cast<int64_t>(off) + binLen);
        int64_t key = keyToLongV(table, rec.key);
        int64_t decoded = 0;
        size_t pos = 0;
        bool recBad = false;
        std::string recErr;
        while (pos < bin.size()) {
            DecodedRef r = decodeRef(bin, pos);
            if (!r.valid) {
                badRefs++;
                recBad = true;
                recErr = r.error;
                break;
            }
            decoded++;
            totalRefs++;
            typeCounts[r.type]++;
            sourceCounts[refSourceName(r.flags)]++;
            if (r.symbolID >= 0) {
                withSymbolId++;
            }
            if (r.flags & (0x04 | 0x10)) {
                offsetOrShift++;
            }
            if ((limit < 0 || count < limit) && (limit < 0 || decoded <= 8)) {
                uint64_t from = isFrom ? static_cast<uint64_t>(key) : r.addrKey;
                uint64_t to = isFrom ? r.addrKey : static_cast<uint64_t>(key);
                std::cout << "  key=" << key << " from=" << hexKey(from)
                          << " to=" << hexKey(to) << " type=" << refTypeName(r.type)
                          << " op=" << static_cast<int>(r.opIndex)
                          << (r.flags & 0x02 ? " primary" : "")
                          << " src=" << refSourceName(r.flags);
                if (r.symbolID >= 0) {
                    std::cout << " sym=" << r.symbolID;
                }
                std::cout << "\n";
            }
        }
        if (decoded != numRefs) {
            recBad = true;
            recErr = "count mismatch: header=" + std::to_string(numRefs) +
                     " decoded=" + std::to_string(decoded);
        }
        if (recBad) {
            badRecords++;
            std::cout << "  BAD RECORD key=" << key << " (" << recErr << ")\n";
            return;
        }
        okRecords++;
        count++;
    });
    std::cout << "  decoded " << totalRefs << " refs in " << okRecords << " records ("
              << badRecords << " bad records, " << badRefs << " bad refs); symbol ids: "
              << withSymbolId << "; offset/shift refs: " << offsetOrShift << "\n";
    if (!typeCounts.empty() || !sourceCounts.empty()) {
        std::cout << "  ref types:";
        for (const auto& kv : typeCounts) {
            std::cout << " " << refTypeName(kv.first) << "=" << kv.second;
        }
        std::cout << "\n  sources:";
        for (const auto& kv : sourceCounts) {
            std::cout << " " << kv.first << "=" << kv.second;
        }
        std::cout << "\n";
    }
    if (limit >= 0 && count >= limit && table.recordCount > count) {
        std::cout << "  ... (" << (table.recordCount - count) << " more records)\n";
    }
}

void dumpChain(const GbfReader& gbf, int32_t id, int maxBytes) {
    try {
        std::vector<uint8_t> data = gbf.readChainedBuffer(id);
        std::cout << "chain " << id << ": " << data.size() << " bytes\n";
        size_t n = static_cast<size_t>(maxBytes) < data.size() ? static_cast<size_t>(maxBytes)
                                                               : data.size();
        static const char* kHex = "0123456789abcdef";
        for (size_t i = 0; i < n; i++) {
            if (i % 16 == 0) {
                std::cout << "  " << std::setw(6) << std::hex << i << std::dec << ": ";
            }
            std::cout << kHex[data[i] >> 4] << kHex[data[i] & 0xF] << " ";
            if (i % 16 == 15 || i + 1 == n) {
                std::cout << "\n";
            }
            if (i + 1 >= 512) {
                std::cout << "  ... (hex truncated)\n";
                break;
            }
        }
        if (n >= 2 && data[0] == 'M' && data[1] == 'Z') {
            std::cout << "  detected PE file header (MZ)\n";
        }
    } catch (const std::exception& e) {
        std::cout << "  ERROR: " << e.what() << "\n";
    }
}

int usage() {
std::cout << "usage: enigma_gzf_inspect <db.gbf | dir.rep | file.gzf> [--table NAME]\n"
             "                          [--limit N] [--all] [--chain ID] [--program NAME]\n"
             "                          [--filebytes OUT]\n";
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    std::string source;
    std::string tableFilter;
    std::string programFilter;
    std::string fileBytesOut;
    bool dumpAll = false;
    bool haveChain = false;
    int chainId = -1;
    int limit = kDefaultLimit;

    std::vector<std::string> args(argv + 1, argv + argc);
    for (size_t i = 0; i < args.size(); i++) {
        const std::string& a = args[i];
        if (a == "--table" && i + 1 < args.size()) {
            tableFilter = args[++i];
        } else if (a == "--limit" && i + 1 < args.size()) {
            limit = std::atoi(args[++i].c_str());
        } else if (a == "--all") {
            dumpAll = true;
        } else if (a == "--chain" && i + 1 < args.size()) {
            chainId = std::atoi(args[++i].c_str());
            haveChain = true;
        } else if (a == "--program" && i + 1 < args.size()) {
            programFilter = args[++i];
        } else if (a == "--filebytes" && i + 1 < args.size()) {
            fileBytesOut = args[++i];
        } else if (a == "--help" || a == "-h") {
            return usage();
        } else if (source.empty()) {
            source = a;
        } else {
            std::cerr << "unexpected argument: " << a << "\n";
            return usage();
        }
    }
    if (source.empty()) {
        return usage();
    }

    try {
        // Case 1: direct .gbf database.
        if (GbfReader::isGbfFile(source)) {
            GbfReader gbf(source);
            printInventory(gbf);
            if (!fileBytesOut.empty()) {
                std::string name;
                std::vector<uint8_t> bytes;
                if (!extractFileBytes(gbf, name, bytes)) {
                    std::cerr << "no readable File Bytes in this database\n";
                    return 1;
                }
                std::ofstream fout(fileBytesOut, std::ios::binary);
                fout.write(reinterpret_cast<const char*>(bytes.data()),
                           static_cast<std::streamsize>(bytes.size()));
                std::cout << "wrote " << bytes.size() << " bytes (" << name
                          << ") -> " << fileBytesOut << "\n";
                return 0;
            }
            if (haveChain) {
                dumpChain(gbf, chainId, limit < 1 ? 512 : limit);
            } else if (dumpAll) {
                for (const GbfTableSchema& t : gbf.tables()) {
                    dumpTable(gbf, t, limit);
                }
            } else if (!tableFilter.empty()) {
                const GbfTableSchema* t = gbf.findTable(tableFilter);
                if (t == nullptr) {
                    std::cerr << "no such table: " << tableFilter << "\n";
                    return 1;
                }
                if (tableFilter == "FROM REFS" || tableFilter == "TO REFS") {
                    dumpRefsTable(gbf, *t, limit);
                } else {
                    dumpTable(gbf, *t, limit);
                }
            }
            return 0;
        }

        // Case 2: project directory or archive.
        RepProject project(source);
        std::cout << "project: " << project.projectName() << "\n";
        for (const RepProgram& p : project.programs()) {
            std::cout << "  id=" << std::uppercase << std::hex << p.id << std::dec << " "
                      << p.name << (p.isProgram ? " [Program]" : "") << "\n";
        }

        std::vector<RepProgram> selected;
        for (const RepProgram& p : project.programs()) {
            if (!p.isProgram) {
                continue;
            }
            if (!programFilter.empty() && p.name != programFilter) {
                continue;
            }
            selected.push_back(p);
        }
        for (const RepProgram& p : selected) {
            std::cout << "\n== program: " << p.name << " (" << p.dbBase << ") ==\n";
            std::vector<uint8_t> dbBytes = project.getDatabaseBytes(p);
            std::unique_ptr<GbfReader> gbf = GbfReader::fromMemory(std::move(dbBytes));
            printInventory(*gbf);
            if (!fileBytesOut.empty()) {
                std::string name;
                std::vector<uint8_t> bytes;
                if (!extractFileBytes(*gbf, name, bytes)) {
                    std::cerr << "no readable File Bytes in this database\n";
                    return 1;
                }
                std::ofstream fout(fileBytesOut, std::ios::binary);
                fout.write(reinterpret_cast<const char*>(bytes.data()),
                           static_cast<std::streamsize>(bytes.size()));
                std::cout << "wrote " << bytes.size() << " bytes (" << name
                          << ") -> " << fileBytesOut << "\n";
                return 0;
            }
            if (haveChain) {
                dumpChain(*gbf, chainId, limit < 1 ? 512 : limit);
            } else if (dumpAll) {
                for (const GbfTableSchema& t : gbf->tables()) {
                    dumpTable(*gbf, t, limit);
                }
            } else if (!tableFilter.empty()) {
                const GbfTableSchema* t = gbf->findTable(tableFilter);
                if (t == nullptr) {
                    std::cerr << "no such table in " << p.name << ": " << tableFilter << "\n";
                    return 1;
                }
                if (tableFilter == "FROM REFS" || tableFilter == "TO REFS") {
                    dumpRefsTable(*gbf, *t, limit);
                } else {
                    dumpTable(*gbf, *t, limit);
                }
            }
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}