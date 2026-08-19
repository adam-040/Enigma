/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ghidra {

/**
 * Field type codes as stored in the master table "FieldTypes" column.
 * (db.Schema field class ids.)
 */
enum class GbfFieldType : uint8_t {
    Byte = 0,
    Short = 1,
    Int = 2,
    Long = 3,
    String = 4,
    Binary = 5,
    Bool = 6,
    Fixed10 = 7
};

/**
 * Node type codes stored in the first byte of each Gbf data block.
 * (db.NodeMgr)
 */
enum class GbfNodeType : uint8_t {
    LongKeyInterior = 0,
    LongKeyVarRec = 1,
    LongKeyFixedRec = 2,
    VarKeyInterior = 3,
    VarKeyRec = 4,
    FixedKeyInterior = 5,
    FixedKeyVarRec = 6,
    FixedKeyFixedRec = 7,
    ChainedBufferIndex = 8,
    ChainedBufferData = 9
};

/**
 * Decoded schema of one database table, as read from the master table record.
 */
struct GbfTableSchema {
    std::string name;
    int32_t version = 0;
    int32_t rootBufferId = 0;

    /** Raw key type code byte (0..7 plain field code, or indexed (primary<<4)|indexed). */
    int32_t keyTypeCode = 0;

    std::vector<GbfFieldType> fieldTypes;
    std::vector<std::string> fieldNames;
    int32_t indexedColumn = -1;
    int64_t maxKey = 0;
    int64_t recordCount = 0;

    /** Column indexes stored sparsely (record data holds only non-null sparse fields). */
    std::vector<int32_t> sparseColumns;

    /** True for secondary index tables whose key is an IndexField (primary<<4|indexed). */
    bool isIndexTable() const { return (keyTypeCode & 0xF0) != 0; }

    /** Fixed key byte length, or -1 if the key type is variable length. */
    int32_t keySize() const;

    /** Size of one record when all columns are fixed length, or -1 for variable records. */
    int32_t fixedRecordSize() const;

    bool hasSparseColumns() const { return !sparseColumns.empty(); }
};

/**
 * One database record: raw key bytes and record data region.
 *
 * For variable-length record nodes "data" holds the full record field region
 * (an expanded chained buffer when the record points to one).  Columns stored
 * sparsely are decoded into sparseFields as {columnIndex, raw value bytes}.
 */
struct GbfRecord {
    std::vector<uint8_t> key;
    std::vector<uint8_t> data;
    std::vector<std::pair<int32_t, std::vector<uint8_t>>> sparseFields;
};

/**
 * Reader for the Ghidra database buffer format (.gbf / "LocalBufferFile").
 *
 * Parses the container header, container parameter entries, the DBParms
 * block, the block table and the master table, then walks any table's B-tree
 * to produce records.  All multi-byte values are big-endian as stored on disk.
 *
 * The binary layout was derived from the Ghidra "db" package sources
 * (db.BufferMgr, db.MasterTable, db.LongKeyInteriorNode, db.ChainedBuffer,
 * db.SparseRecord and the ghidra.program.database adapters).
 */
class GbfReader {
public:
    /** Magic value of a Gbf container header. */
    static constexpr uint64_t kMagic = 0x2f30312c34292c2aULL;

    /** Opens a Gbf file; throws std::runtime_error if the file is not Gbf. */
    explicit GbfReader(const std::string& filePath);

    /** Constructs a reader over in-memory Gbf bytes (e.g. from a Gzf archive). */
    static std::unique_ptr<GbfReader> fromMemory(std::vector<uint8_t> bytes);

    static bool isGbfFile(const std::string& filePath);

    uint64_t fileId() const { return fileId_; }
    int32_t headerVersion() const { return headerVersion_; }
    uint32_t blockSize() const { return blockSize_; }
    int32_t firstFreeBufferId() const { return firstFreeId_; }

    /** DBParms of block 0: raw name -> value pairs of the parm index table. */
    const std::vector<std::pair<std::string, int32_t>>& parameters() const { return parms_; }

    /** Tables as decoded from the master table (index tables included). */
    const std::vector<GbfTableSchema>& tables() const { return tables_; }

    /** Finds a table by (case sensitive) name; nullptr if not present. */
    const GbfTableSchema* findTable(const std::string& name) const;

    /**
     * Walks the B-tree of the given table and invokes fn for every record in
     * key order.  Throws std::runtime_error on malformed data.
     */
    void visitRecords(const GbfTableSchema& table,
        const std::function<void(const GbfRecord&)>& fn) const;

    /**
     * Reads the full contents of a chained buffer (single data node or
     * multi-block indexed chain).  Uninitialized chunks read as zeros.
     */
    std::vector<uint8_t> readChainedBuffer(int32_t bufferId) const;

    // ------------------------------------------------------------------
    // Field helpers: big-endian readers over arbitrary byte regions.
    // ------------------------------------------------------------------

    /** Reads a fixed-size numeric field (Byte/Short/Int/Long/Bool). */
    static int64_t readNumField(GbfFieldType type, const uint8_t* p, size_t size, size_t& off);

    /** Reads a String field; returns with value="" for a null string. */
    static bool readStringField(const uint8_t* p, size_t size, size_t& off, std::string& value);

    /** Reads a Binary field; returns vector (empty for null). */
    static std::vector<uint8_t> readBinaryField(const uint8_t* p, size_t size, size_t& off);

    /** Reads a Fixed10 field as 10 raw bytes. */
    static std::vector<uint8_t> readFixed10Field(const uint8_t* p, size_t size, size_t& off);

    /**
     * Reads a field of any supported type and appends a printable
     * representation to out.  Returns the new offset.
     */
    static size_t formatField(GbfFieldType type, const uint8_t* p, size_t size, size_t off,
        std::string& out);

private:
    explicit GbfReader(std::vector<uint8_t> bytes);

    void decodeHeader();
    void readBlocks();
    void decodeMasterTable();
    void collectRecords(const GbfTableSchema& table,
        const std::function<void(const GbfRecord&)>& fn) const;
    const std::vector<uint8_t>& block(int32_t id) const;

    uint64_t fileId_ = 0;
    int32_t headerVersion_ = 0;
    uint32_t blockSize_ = 0;
    int32_t firstFreeId_ = 0;
    std::vector<std::pair<std::string, int32_t>> parms_;
    std::vector<GbfTableSchema> tables_;
    std::vector<std::vector<uint8_t>> blocks_;
    std::vector<uint8_t> fileBytes_;
};

}  // namespace ghidra