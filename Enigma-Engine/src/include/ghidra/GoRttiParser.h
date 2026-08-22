#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace ghidra {

class Memory;
class Program;
class DataTypeManager;
class DataType;

/**
 * Parses Go runtime type information (RTTI) from pclntab type records.
 * Go type records contain kind, size, hash, field offsets, and method info.
 */
class GoRttiParser {
public:
    struct GoType {
        uint64_t address = 0;
        uint8_t kind = 0;
        uint64_t size = 0;
        uint64_t hash = 0;
        std::string name;
        std::vector<std::pair<std::string, uint64_t>> fields;
        std::vector<uint64_t> methodOffsets;
        bool valid = false;
    };

    /**
     * Parse Go type records from pclntab.
     * @param memory The program memory
     * @param pclntabStart Start address of pclntab section
     * @param pclntabSize Size of pclntab section
     * @param is64 Whether this is a 64-bit binary
     * @return Map of type address -> GoType
     */
    static std::unordered_map<uint64_t, GoType> parseTypes(
        Memory* memory, const Address& pclntabStart, int64_t pclntabSize, bool is64);

    /**
     * Create Ghidra DataType objects from parsed Go types.
     */
    static void createDataTypes(
        const std::unordered_map<uint64_t, GoType>& types,
        DataTypeManager* dtm);

    /**
     * Get the Go kind name from a kind value.
     */
    static std::string getKindName(uint8_t kind);

private:
    static constexpr uint8_t KIND_BOOL = 1;
    static constexpr uint8_t KIND_INT = 2;
    static constexpr uint8_t KIND_INT8 = 3;
    static constexpr uint8_t KIND_INT16 = 4;
    static constexpr uint8_t KIND_INT32 = 5;
    static constexpr uint8_t KIND_INT64 = 6;
    static constexpr uint8_t KIND_UINT = 7;
    static constexpr uint8_t KIND_UINT8 = 8;
    static constexpr uint8_t KIND_UINT16 = 9;
    static constexpr uint8_t KIND_UINT32 = 10;
    static constexpr uint8_t KIND_UINT64 = 11;
    static constexpr uint8_t KIND_UINTPTR = 12;
    static constexpr uint8_t KIND_FLOAT32 = 13;
    static constexpr uint8_t KIND_FLOAT64 = 14;
    static constexpr uint8_t KIND_COMPLEX64 = 15;
    static constexpr uint8_t KIND_COMPLEX128 = 16;
    static constexpr uint8_t KIND_ARRAY = 17;
    static constexpr uint8_t KIND_STRUCT = 18;
    static constexpr uint8_t KIND_POINTER = 22;
    static constexpr uint8_t KIND_STRING = 23;
    static constexpr uint8_t KIND_SLICE = 23;
    static constexpr uint8_t KIND_FUNC = 24;
    static constexpr uint8_t KIND_INTERFACE = 25;
    static constexpr uint8_t KIND_MAP = 26;
    static constexpr uint8_t KIND_CHAN = 27;
};

} // namespace ghidra
