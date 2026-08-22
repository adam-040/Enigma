#include <ghidra/SwiftTypeMetadataAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Msg.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/IntegerDataType.h>
#include <cstdint>
#include <string>
#include <vector>
#include <cctype>
#include <algorithm>

namespace ghidra {

namespace {

// Swift 5 type descriptor kinds (bits 0-4 of flags)
enum SwiftDescriptorKind : uint8_t {
    SWIFT_KIND_MODULE       = 0,
    SWIFT_KIND_EXTENSION    = 1,
    SWIFT_KIND_ANONYMOUS    = 2,
    SWIFT_KIND_PROTOCOL     = 3,
    SWIFT_KIND_CLASS        = 4,
    SWIFT_KIND_STRUCT       = 5,
    SWIFT_KIND_ENUM         = 6,
    SWIFT_KIND_OPAQUE_TYPE  = 7,
};

static const char* kindToTypeName(uint8_t kind) {
    switch (kind) {
        case SWIFT_KIND_CLASS:   return "(class)";
        case SWIFT_KIND_STRUCT:  return "(struct)";
        case SWIFT_KIND_ENUM:    return "(enum)";
        case SWIFT_KIND_PROTOCOL: return "(protocol)";
        case SWIFT_KIND_MODULE:  return "(module)";
        default:                 return "(type)";
    }
}

// Simple Swift 5 name demangler.
// Handles "$s<len><name>..." pattern.
static std::string demangleSwiftName(const std::string& mangled) {
    if (mangled.empty()) return mangled;

    std::string result;
    size_t pos = 0;

    // Skip "$s" or "$S" or "_T" prefix
    if (mangled.size() >= 2 && mangled[0] == '$' && mangled[1] == 's') {
        pos = 2;
    } else if (mangled.size() >= 3 && mangled[0] == '$' && mangled[1] == 'S') {
        pos = 3;
    } else if (mangled.size() >= 2 && mangled[0] == '_' && mangled[1] == 'T') {
        pos = 2;
    } else {
        return mangled;
    }

    while (pos < mangled.size()) {
        char c = mangled[pos];
        // Type suffix characters end the identifier chain
        if (c == 'C' || c == 'V' || c == 'O' || c == 'P' ||
            c == 'D' || c == 'S' || c == 'M' || c == 'm' ||
            c == 'F' || c == 'f' || c == 'I' || c == 'i' ||
            c == 'T' || c == 't') {
            break;
        }
        // Read length-prefixed identifier
        if (c < '0' || c > '9') break;

        int len = 0;
        while (pos < mangled.size() && mangled[pos] >= '0' && mangled[pos] <= '9') {
            len = len * 10 + (mangled[pos] - '0');
            ++pos;
        }
        if (len <= 0 || pos + len > mangled.size()) break;

        if (!result.empty()) result += '.';
        result += mangled.substr(pos, len);
        pos += len;
    }

    if (result.empty()) return mangled;
    return result;
}

static int32_t readInt32LE(Memory* memory, const Address& addr) {
    uint8_t bytes[4] = {};
    MemoryBlock* block = memory->getBlock(addr);
    if (!block) return 0;
    block->getBytes(addr, bytes, 4);
    return static_cast<int32_t>(
        static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24));
}

static uint32_t readUInt32LE(Memory* memory, const Address& addr) {
    uint8_t bytes[4] = {};
    MemoryBlock* block = memory->getBlock(addr);
    if (!block) return 0;
    block->getBytes(addr, bytes, 4);
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

static std::string readCString(Memory* memory, const Address& addr, int maxLen = 256) {
    std::string s;
    for (int i = 0; i < maxLen; ++i) {
        Address cur(addr.getAddressSpace(), addr.getOffset() + i);
        MemoryBlock* b = memory->getBlock(cur);
        if (!b) break;
        uint8_t byte = b->getByte(cur);
        if (byte == 0) break;
        s += static_cast<char>(byte);
    }
    return s;
}

// Resolve a Swift relative offset.
// target = fieldAddr + offset (with bit 0 masking for indirect flag).
static Address resolveOffset(const Address& fieldAddr, int32_t offset) {
    bool indirect = (offset & 1) != 0;
    int64_t base = fieldAddr.getOffset() + static_cast<int64_t>(offset & ~1);
    return Address(fieldAddr.getAddressSpace(), base);
}

// Read a 64-bit pointer at an address.
static uint64_t readUInt64LE(Memory* memory, const Address& addr) {
    uint8_t bytes[8] = {};
    MemoryBlock* block = memory->getBlock(addr);
    if (!block) return 0;
    block->getBytes(addr, bytes, 8);
    return static_cast<uint64_t>(bytes[0]) |
           (static_cast<uint64_t>(bytes[1]) << 8) |
           (static_cast<uint64_t>(bytes[2]) << 16) |
           (static_cast<uint64_t>(bytes[3]) << 24) |
           (static_cast<uint64_t>(bytes[4]) << 32) |
           (static_cast<uint64_t>(bytes[5]) << 40) |
           (static_cast<uint64_t>(bytes[6]) << 48) |
           (static_cast<uint64_t>(bytes[7]) << 56);
}

// Sanitize a string for use as a label.
static std::string sanitizeLabel(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out += c;
        } else {
            out += '_';
        }
    }
    return out;
}

// Process a __swift5_types section block.
static void processTypesSection(Memory* memory, SymbolTable* symTable,
                                 MemoryBlock* block, TaskMonitor* monitor,
                                 int& typeCount, int& labelCount) {
    Address cur = block->getStart();
    Address end = block->getEnd();

    while (cur <= end && !monitor->isCancelled()) {
        int32_t raw = readInt32LE(memory, cur);
        if (raw == 0) {
            cur = Address(cur.getAddressSpace(), cur.getOffset() + 4);
            continue;
        }

        bool indirect = (raw & 1) != 0;
        Address descAddr = resolveOffset(cur, raw);

        if (!descAddr.isValid()) {
            cur = Address(cur.getAddressSpace(), cur.getOffset() + 4);
            continue;
        }

        MemoryBlock* descBlock = memory->getBlock(descAddr);
        if (!descBlock) {
            cur = Address(cur.getAddressSpace(), cur.getOffset() + 4);
            continue;
        }

        // If indirect, descAddr points to a pointer which points to the actual descriptor
        Address finalDescAddr = descAddr;
        if (indirect) {
            uint64_t ptrVal = readUInt64LE(memory, descAddr);
            if (ptrVal == 0) {
                cur = Address(cur.getAddressSpace(), cur.getOffset() + 4);
                continue;
            }
            finalDescAddr = Address(descAddr.getAddressSpace(), static_cast<int64_t>(ptrVal));
            if (!memory->getBlock(finalDescAddr)) {
                cur = Address(cur.getAddressSpace(), cur.getOffset() + 4);
                continue;
            }
        }

        uint32_t flags = readUInt32LE(memory, finalDescAddr);
        uint8_t kind = static_cast<uint8_t>(flags & 0x1F);

        // For nominal types and protocols, name is at descriptor offset 8
        if (kind == SWIFT_KIND_CLASS || kind == SWIFT_KIND_STRUCT ||
            kind == SWIFT_KIND_ENUM || kind == SWIFT_KIND_PROTOCOL) {

            Address nameRelAddr(finalDescAddr.getAddressSpace(), finalDescAddr.getOffset() + 8);
            int32_t nameRel = readInt32LE(memory, nameRelAddr);

            if (nameRel != 0) {
                Address nameAddr = resolveOffset(nameRelAddr, nameRel);
                MemoryBlock* nameBlock = memory->getBlock(nameAddr);
                if (nameBlock) {
                    std::string mangled = readCString(memory, nameAddr);
                    if (!mangled.empty()) {
                        std::string demangled = demangleSwiftName(mangled);
                        std::string label = "swift_" + sanitizeLabel(demangled);

                        Symbol* sym = symTable->createLabel(finalDescAddr, label, SourceType::ANALYSIS);
                        if (sym) {
                            ++labelCount;
                        }
                    }
                }
            }
        }

        ++typeCount;
        cur = Address(cur.getAddressSpace(), cur.getOffset() + 4);
    }
}

// Process a __swift5_fieldmd section block.
// Field descriptors contain field records for struct/class/enum types.
static void processFieldMetadataSection(Memory* memory, SymbolTable* symTable,
                                         MemoryBlock* block, TaskMonitor* monitor,
                                         int& fieldCount, int& labelCount) {
    Address cur = block->getStart();
    Address end = block->getEnd();
    AddressSpace* space = cur.getAddressSpace();

    while (cur <= end && !monitor->isCancelled()) {
        // Each entry is a 32-bit relative pointer to a field descriptor
        int32_t raw = readInt32LE(memory, cur);
        if (raw == 0) {
            cur = Address(space, cur.getOffset() + 4);
            continue;
        }

        Address descAddr = resolveOffset(cur, raw);
        if (!descAddr.isValid() || !memory->getBlock(descAddr)) {
            cur = Address(space, cur.getOffset() + 4);
            continue;
        }

        // Field descriptor layout:
        // offset 0: uint32_t record kind (0=struct, 1=class, 2=enum, 3=composite)
        // offset 4: int32_t mangled type name relative offset
        // offset 8: uint16_t superclass relative offset (class only)
        // offset 10: uint16_t reserved
        // offset 12: uint32_t num fields
        // offset 16: field record entries...

        uint32_t recordKind = readUInt32LE(memory, descAddr);
        Address nameRelAddr(space, descAddr.getOffset() + 4);
        int32_t nameRel = readInt32LE(memory, nameRelAddr);

        std::string typeName;
        if (nameRel != 0) {
            Address nameAddr = resolveOffset(nameRelAddr, nameRel);
            if (memory->getBlock(nameAddr)) {
                std::string mangled = readCString(memory, nameAddr);
                typeName = demangleSwiftName(mangled);
            }
        }

        uint32_t numFieldsAddr = descAddr.getOffset() + 12;
        uint32_t numFields = readUInt32LE(memory, Address(space, static_cast<int64_t>(numFieldsAddr)));

        // Create a label for the field descriptor itself
        if (!typeName.empty()) {
            std::string label = "swift_fields_" + sanitizeLabel(typeName);
            symTable->createLabel(descAddr, label, SourceType::ANALYSIS);
            ++labelCount;
        }

        // Parse field records (each field record is 16 bytes minimum)
        Address fieldRecAddr(space, descAddr.getOffset() + 16);
        for (uint32_t fi = 0; fi < numFields && fi < 256; ++fi) {
            if (monitor->isCancelled()) break;

            // Field record layout:
            // offset 0: int32_t mangled field name relative offset
            // offset 4: int32_t mangled type name relative offset
            // offset 8: uint16_t flags
            // offset 10: uint16_t reserved
            // offset 12: int32_t field offset relative to (for class, fixed parts)
            int32_t fieldNameRel = readInt32LE(memory, fieldRecAddr);
            int32_t fieldTypeRel = readInt32LE(memory, Address(space, fieldRecAddr.getOffset() + 4));

            std::string fieldName;
            if (fieldNameRel != 0) {
                Address fnAddr = resolveOffset(fieldRecAddr, fieldNameRel);
                if (memory->getBlock(fnAddr)) {
                    fieldName = readCString(memory, fnAddr);
                }
            }

            std::string fieldTypeName;
            if (fieldTypeRel != 0) {
                Address ftAddr = resolveOffset(fieldRecAddr, fieldTypeRel);
                if (memory->getBlock(ftAddr)) {
                    std::string mangledType = readCString(memory, ftAddr);
                    fieldTypeName = demangleSwiftName(mangledType);
                }
            }

            if (!fieldName.empty() && !fieldTypeName.empty()) {
                // Create a label for the field
                std::string fieldLabel = typeName + "." + fieldName;
                symTable->createLabel(fieldRecAddr, "swift_field_" + sanitizeLabel(fieldLabel),
                                      SourceType::ANALYSIS);
                ++labelCount;
                ++fieldCount;
            }

            fieldRecAddr = Address(space, fieldRecAddr.getOffset() + 16);
        }

        cur = Address(space, cur.getOffset() + 4);
    }
}

// Process a __swift5_assocty section block (associated type descriptors).
static void processAssociatedTypeSection(Memory* memory, SymbolTable* symTable,
                                          MemoryBlock* block, TaskMonitor* monitor,
                                          int& assocCount) {
    Address cur = block->getStart();
    Address end = block->getEnd();
    AddressSpace* space = cur.getAddressSpace();

    while (cur <= end && !monitor->isCancelled()) {
        int32_t raw = readInt32LE(memory, cur);
        if (raw == 0) {
            cur = Address(space, cur.getOffset() + 4);
            continue;
        }

        Address descAddr = resolveOffset(cur, raw);
        if (!descAddr.isValid() || !memory->getBlock(descAddr)) {
            cur = Address(space, cur.getOffset() + 4);
            continue;
        }

        // Associated type descriptor:
        // offset 0: int32_t conforming type relative offset
        // offset 4: int32_t protocol type relative offset
        // offset 8: uint32_t num associated types
        // offset 12: associated type records...

        int32_t conformingRel = readInt32LE(memory, descAddr);
        int32_t protocolRel = readInt32LE(memory, Address(space, descAddr.getOffset() + 4));

        std::string conformingName;
        if (conformingRel != 0) {
            Address nameAddr = resolveOffset(descAddr, conformingRel);
            if (memory->getBlock(nameAddr)) {
                conformingName = demangleSwiftName(readCString(memory, nameAddr));
            }
        }

        std::string protocolName;
        if (protocolRel != 0) {
            Address nameAddr = resolveOffset(descAddr, protocolRel);
            if (memory->getBlock(nameAddr)) {
                protocolName = demangleSwiftName(readCString(memory, nameAddr));
            }
        }

        if (!conformingName.empty()) {
            std::string label = "swift_assoc_" + sanitizeLabel(conformingName);
            if (!protocolName.empty()) label += "_impl_" + sanitizeLabel(protocolName);
            symTable->createLabel(descAddr, label, SourceType::ANALYSIS);
            ++assocCount;
        }

        cur = Address(space, cur.getOffset() + 4);
    }
}

} // anonymous namespace

SwiftTypeMetadataAnalyzer::SwiftTypeMetadataAnalyzer()
    : AbstractAnalyzer("Swift Type Metadata Analyzer",
                       "Discovers Swift type metadata records.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(true);
}

bool SwiftTypeMetadataAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;

    // Check if compiler spec is Swift
    std::string langId = program->getLanguageID().getIdAsString();
    if (langId.find("swift") != std::string::npos ||
        langId.find("Swift") != std::string::npos) return true;

    // Check for Swift sections in memory
    if (program->getMemory()) {
        for (auto* block : program->getMemory()->getBlocks()) {
            std::string name = block->getName();
            if (name.find("__swift5_") != std::string::npos) return true;
            if (name.find("swift5_") != std::string::npos) return true;
        }
    }

    return false;
}

bool SwiftTypeMetadataAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;

    monitor->setMessage("Discovering Swift type metadata records...");

    Memory* memory = program->getMemory();
    SymbolTable* symbolTable = program->getSymbolTable();
    if (!memory || !symbolTable) return true;

    int typeCount = 0;
    int labelCount = 0;
    int fieldCount = 0;
    int assocCount = 0;

    for (auto* block : memory->getBlocks()) {
        if (monitor->isCancelled()) break;
        std::string name = block->getName();
        if (name == "__swift5_types" || name.find("__swift5_types") != std::string::npos) {
            processTypesSection(memory, symbolTable, block, monitor, typeCount, labelCount);
        } else if (name == "__swift5_fieldmd" || name.find("__swift5_fieldmd") != std::string::npos) {
            processFieldMetadataSection(memory, symbolTable, block, monitor, fieldCount, labelCount);
        } else if (name == "__swift5_assocty" || name.find("__swift5_assocty") != std::string::npos) {
            processAssociatedTypeSection(memory, symbolTable, block, monitor, assocCount);
        }
    }

    if (typeCount > 0 || fieldCount > 0 || assocCount > 0) {
        Msg::info(getName(), "Discovered " + std::to_string(typeCount) +
                  " Swift types, " + std::to_string(fieldCount) +
                  " field records, " + std::to_string(assocCount) +
                  " associated types, created " + std::to_string(labelCount) + " labels.");
    }

    return true;
}

} // namespace ghidra
