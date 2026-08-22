#include <ghidra/GoRttiParser.h>
#include <ghidra/Memory.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/CategoryPath.h>
#include <cstring>

namespace ghidra {

static uint64_t readU64LE(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]) << 0) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

static uint32_t readU32LE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 0) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

std::string GoRttiParser::getKindName(uint8_t kind) {
    switch (kind) {
        case KIND_BOOL: return "bool";
        case KIND_INT: return "int";
        case KIND_INT8: return "int8";
        case KIND_INT16: return "int16";
        case KIND_INT32: return "int32";
        case KIND_INT64: return "int64";
        case KIND_UINT: return "uint";
        case KIND_UINT8: return "uint8";
        case KIND_UINT16: return "uint16";
        case KIND_UINT32: return "uint32";
        case KIND_UINT64: return "uint64";
        case KIND_UINTPTR: return "uintptr";
        case KIND_FLOAT32: return "float32";
        case KIND_FLOAT64: return "float64";
        case KIND_COMPLEX64: return "complex64";
        case KIND_COMPLEX128: return "complex128";
        case KIND_ARRAY: return "array";
        case KIND_STRUCT: return "struct";
        case KIND_POINTER: return "pointer";
        case KIND_STRING: return "string";
        case KIND_FUNC: return "func";
        case KIND_INTERFACE: return "interface";
        case KIND_MAP: return "map";
        case KIND_CHAN: return "chan";
        default: return "unknown_" + std::to_string(kind);
    }
}

std::unordered_map<uint64_t, GoRttiParser::GoType> GoRttiParser::parseTypes(
    Memory* memory, const Address& pclntabStart, int64_t pclntabSize, bool is64) {
    std::unordered_map<uint64_t, GoType> types;

    if (!memory || pclntabSize < 64) return types;

    std::vector<uint8_t> data(static_cast<size_t>(pclntabSize));
    int got = memory->getBytes(pclntabStart, data.data(), static_cast<int>(pclntabSize));
    if (got != static_cast<int>(pclntabSize)) return types;

    int ptrSize = is64 ? 8 : 4;
    uint64_t baseAddr = pclntabStart.getOffset();

    // Go type records in the _type section follow a specific layout:
    // _type struct:
    //   size uintptr     (ptrSize bytes)
    //   hash uint32      (4 bytes)
    //   tflag uint8      (1 byte)
    //   align uint8      (1 byte)
    //   fieldAlign uint8 (1 byte)
    //   kind uint8       (1 byte)
    //   equal func(ptr, ptr) bool (ptrSize bytes - function pointer)
    //   gcdata *byte     (ptrSize bytes)
    //   str nameOff      (4 bytes - offset to string)
    //   ptrToThis typeOff (4 bytes - offset to pointer type)
    constexpr int TYPE_HEADER_SIZE_64 = 8 + 4 + 1 + 1 + 1 + 1 + 8 + 8 + 4 + 4;  // 40
    constexpr int TYPE_HEADER_SIZE_32 = 4 + 4 + 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4;  // 28

    int typeRecSize = is64 ? TYPE_HEADER_SIZE_64 : TYPE_HEADER_SIZE_32;

    // Scan data for type records - look for valid kind values
    for (int64_t off = 0; off + typeRecSize <= pclntabSize; off += ptrSize) {
        int kindOff = is64 ? 15 : 11;  // size(ptrSize) + hash(4) + tflag(1) + align(1) + fieldAlign(1)
        uint8_t kind = data[static_cast<size_t>(off + kindOff)];

        // Only accept known kind values
        if (kind < KIND_BOOL || kind > KIND_CHAN) continue;

        // Read size field
        uint64_t size = is64 ? readU64LE(&data[static_cast<size_t>(off)])
                              : readU32LE(&data[static_cast<size_t>(off)]);

        // Validate size - should be reasonable
        if (size > 0x1000000) continue; // 16MB max

        // Read hash
        uint32_t hash = readU32LE(&data[static_cast<size_t>(off + (is64 ? 8 : 4))]);

        GoType gt;
        gt.address = baseAddr + off;
        gt.kind = kind;
        gt.size = size;
        gt.hash = hash;
        gt.name = getKindName(kind);
        gt.valid = true;

        types[gt.address] = gt;
    }

    return types;
}

void GoRttiParser::createDataTypes(
    const std::unordered_map<uint64_t, GoType>& types,
    DataTypeManager* dtm) {
    if (!dtm || types.empty()) return;

    CategoryPath goPath("/go");

    // Create base Go types as typedefs
    IntegerDataType intType;
    BooleanDataType boolType;
    FloatDataType float32Type;

    for (const auto& [addr, gt] : types) {
        if (!gt.valid) continue;

        std::string typeName = "go_" + gt.name;

        // Check if type already exists
        DataType* existing = dtm->getDataType(goPath, typeName);
        if (existing) continue;

        // Create a structure for Go types
        StructureDataType* goStruct = new StructureDataType(goPath, typeName, gt.size, dtm);

        // Add standard Go type fields
        goStruct->insertAtOffset(0, &intType, 8, "size", "");
        goStruct->insertAtOffset(8, &intType, 4, "hash", "");
        goStruct->insertAtOffset(12, &boolType, 1, "tflag", "");
        goStruct->insertAtOffset(13, &boolType, 1, "align", "");
        goStruct->insertAtOffset(14, &boolType, 1, "fieldAlign", "");
        goStruct->insertAtOffset(15, &boolType, 1, "kind", "");

        dtm->addDataType(goStruct, nullptr);
    }
}

} // namespace ghidra
