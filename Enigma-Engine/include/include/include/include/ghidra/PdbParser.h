#pragma once
#include <ghidra/DataType.h>
#include <ghidra/Function.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <cstdint>

namespace ghidra {
namespace pdb {

// MSF (Multi-Stream Format) reader
struct PdbStream {
    std::vector<uint8_t> data;
};

class PdbFile {
public:
    bool open(const std::string& path);
    bool valid() const { return good_; }
    uint32_t getStreamSize(uint32_t streamIdx);
    bool getStream(uint32_t streamIdx, std::vector<uint8_t>& out);
    const std::string& getPath() const { return path_; }

    struct Header {
        uint32_t blockSize = 0;   uint32_t numBlocks = 0;
        uint32_t numDirBytes = 0; uint32_t blockMapAddr = 0;
    };
    const Header& getHeader() const { return hdr_; }

private:
    std::string path_;
    std::vector<uint8_t> fileBuf_;
    Header hdr_;
    bool good_ = false;
    std::vector<uint32_t> streamSizes_;
    std::vector<std::vector<uint32_t>> streamBlockLists_;
    bool readStreamDirectory();
};

// TPI type records
struct PdbType {
    enum Kind { UNKNOWN, PROCEDURE, POINTER, ARGLIST, SIMPLE, STRUCT, UNION, ENUM, ARRAY, MODIFIER, TYPEDEF };
    Kind kind = UNKNOWN;
    std::string name;
    uint32_t returnTypeId = 0;  // for PROCEDURE
    uint32_t argListId = 0;     // for PROCEDURE
    uint32_t pointeeId = 0;     // for POINTER
    uint32_t baseTypeId = 0;    // for TYPEDEF/MODIFIER
    uint32_t elementTypeId = 0; // for ARRAY
    uint64_t size = 0;
    uint8_t ptrSize = 8;
    uint8_t callConv = 0;
    std::vector<uint32_t> memberTypeIds; // for ARGLIST
    std::string udtName; // for STRUCT/UNION/ENUM
};

class PdbTypeReader {
public:
    bool parseTpi(PdbFile& pdb, uint32_t tpiStreamIdx);
    bool parseIpi(PdbFile& pdb, uint32_t ipiStreamIdx);
    const PdbType* getType(uint32_t idx) const;
    DataType* resolveType(uint32_t idx, DataTypeManager* dtm,
        std::unordered_map<uint32_t, DataType*>& cache) const;

private:
    std::unordered_map<uint32_t, PdbType> types_;
    bool parseRecords(const uint8_t* data, uint32_t size);
};

// Symbol records
struct PdbSymbol {
    uint32_t type = 0;
    std::string name;
    uint32_t segment = 0; uint64_t offset = 0;
    uint32_t typeIndex = 0;
    uint64_t codeStart = 0; uint64_t codeEnd = 0;
};

class PdbSymbolReader {
public:
    bool parseGlobalSymbols(PdbFile& pdb, uint32_t streamIdx);
    bool parseModuleSymbols(PdbFile& pdb, const std::vector<uint8_t>& modStream, uint64_t sectionBase);
    const std::vector<PdbSymbol>& getFunctions() const { return functions_; }
    const std::vector<PdbSymbol>& getGlobals() const { return globals_; }
    uint64_t sectionToVA(uint32_t seg, uint64_t off) const;

    void setSectionBases(const std::map<uint32_t, uint64_t>& bases) { sectionBases_ = bases; }

private:
    std::vector<PdbSymbol> functions_;
    std::vector<PdbSymbol> globals_;
    std::map<uint32_t, uint64_t> sectionBases_;
};

// DBI stream parser
struct DbiInfo {
    uint32_t globalStreamIdx = 0;
    uint32_t publicStreamIdx = 0;
    uint32_t symRecordStreamIdx = 0;
    uint32_t moduleCount = 0;
    bool parsed = false;
};

class PdbDbiReader {
public:
    bool parse(PdbFile& pdb, DbiInfo& info, std::map<uint32_t, uint64_t>& sectionBases);
};

} // namespace pdb
} // namespace ghidra
