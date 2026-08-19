/* ###
 * IP: Enigma Engine (original work)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GzfProgramImporter.cpp
/// \brief Native .gbf -> ProgramDB importer (P3a: memory, listing, symbols).
///
/// Table/record layouts mirror the Ghidra program database as produced by
/// ghidra.program.database (verified against real corpora: notepad_test.exe
/// and key.exe databases).  Column semantics were cross-checked against the
/// Ghidra adapter sources (MemoryMapDBAdapterV3, FileBytesAdapterV0,
/// InstDBAdapter, ProtoDBAdapterV1, SymbolDatabaseAdapterV5, FunctionAdapter,
/// ThunkFunctionAdapter, CallingConventionDBAdapter, CommentsDBAdapterV1).
///
/// Db keys: master-table "key=N" prints the db.KeyType ordinal; N=3 tables
/// (Memory Blocks, Sub Memory Blocks, File Bytes, Instructions, Prototypes,
/// Symbols, Function Data, Thunk Functions, Comments, Metadata) carry
/// 8-byte big-endian long keys; N=0 (Calling Conventions) 1-byte keys;
/// N=4 (Program) string keys.
#include "ghidra/import/GzfProgramImporter.h"

#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/Category.h>
#include <ghidra/CharDataType.h>
#include <ghidra/DataTypeComponentImpl.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataOrganizationImpl.h>
#include <ghidra/Disassembler.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/EquateTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/Float16DataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/IBO32DataType.h>
#include <ghidra/IBO64DataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/Instruction.h>
#include <ghidra/Listing.h>
#include <ghidra/LongDataType.h>
#include <ghidra/LongLongDataType.h>
#include <ghidra/Memory.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/Namespace.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/SourceFileManager.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/LocalVariableImpl.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/RefType.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RelocationTableImpl.h>
#include <ghidra/Register.h>
#include <ghidra/ShortDataType.h>
#include <ghidra/SourceType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/TerminatedStringDataType.h>
#include <ghidra/TerminatedUnicode32DataType.h>
#include <ghidra/TerminatedUnicodeDataType.h>
#include <ghidra/TreeManager.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/Undefined1DataType.h>
#include <ghidra/Undefined2DataType.h>
#include <ghidra/Undefined4DataType.h>
#include <ghidra/Undefined8DataType.h>
#include <ghidra/UnicodeDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/UnsignedCharDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/UnsignedLongLongDataType.h>
#include <ghidra/UnsignedShortDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/WideChar16DataType.h>
#include <ghidra/WideCharDataType.h>
#include <ghidra/WordDataType.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <unordered_map>
#include <sstream>
#include <stdexcept>
#include <string>

namespace ghidra {

namespace {

// db.KeyType ordinals: BYTE=0, SHORT=1, INT=2, LONG=3, STRING=4.
constexpr int KEY_TYPE_STRING = 4;

// Address-map key space markers (RefListV0/AddressMap encoding): the high 32
// bits identify the address space.  0x20000000 = image (default) space,
// 0x40000000 = stack space, 0x50000000 = external space.  Verified against
// notepad/key/pro corpora.
constexpr uint64_t ADDR_KEY_IMAGE_SPACE = 0x20000000ull;
constexpr uint64_t ADDR_KEY_STACK_SPACE = 0x40000000ull;
constexpr uint64_t ADDR_KEY_EXT_SPACE = 0x50000000ull;

// RefListFlagsV0 flag bits (ghidra.program.database.references.RefListFlagsV0).
constexpr uint8_t REF_FLAG_SOURCE_LOBIT = 0x01;
constexpr uint8_t REF_FLAG_PRIMARY = 0x02;
constexpr uint8_t REF_FLAG_OFFSET = 0x04;
constexpr uint8_t REF_FLAG_HAS_SYMBOL_ID = 0x08;
constexpr uint8_t REF_FLAG_SHIFT = 0x10;
constexpr uint8_t REF_FLAG_SOURCE_HIBITS = 0x60;

// SourceType storage ids (SourceType.java); DEFAULT=2 and ANALYSIS=0 are
// remapped inside RefListFlagsV0 (0=DEFAULT, 2=ANALYSIS, else storage id).
SourceType decodeRefSource(uint8_t flags) {
    const int id = static_cast<int>(((flags & REF_FLAG_SOURCE_HIBITS) >> 4) |
                                    (flags & REF_FLAG_SOURCE_LOBIT));
    switch (id) {
        case 1: return SourceType::USER_DEFINED;
        case 2: return SourceType::ANALYSIS;
        case 3: return SourceType::IMPORTED;
        case 4: return SourceType::AI;
        default: return SourceType::DEFAULT;
    }
}

// RefType value bytes (RefType.java) -> static instances (RefTypes).
const RefType* refTypeByValue(int8_t v) {
    switch (v) {
        case RefType::__INVALID: return &RefTypes::INVALID;
        case RefType::__UNKNOWNFLOW: return &RefTypes::FLOW;
        case RefType::__FALL_THROUGH: return &RefTypes::FALL_THROUGH;
        case RefType::__UNCONDITIONAL_JUMP: return &RefTypes::UNCONDITIONAL_JUMP;
        case RefType::__CONDITIONAL_JUMP: return &RefTypes::CONDITIONAL_JUMP;
        case RefType::__UNCONDITIONAL_CALL: return &RefTypes::UNCONDITIONAL_CALL;
        case RefType::__CONDITIONAL_CALL: return &RefTypes::CONDITIONAL_CALL;
        case RefType::__TERMINATOR: return &RefTypes::TERMINATOR;
        case RefType::__COMPUTED_JUMP: return &RefTypes::COMPUTED_JUMP;
        case RefType::__CONDITIONAL_TERMINATOR: return &RefTypes::CONDITIONAL_TERMINATOR;
        case RefType::__COMPUTED_CALL: return &RefTypes::COMPUTED_CALL;
        case RefType::__INDIRECTION: return &RefTypes::INDIRECTION;
        case RefType::__CALL_TERMINATOR: return &RefTypes::CALL_TERMINATOR;
        case RefType::__JUMP_TERMINATOR: return &RefTypes::JUMP_TERMINATOR;
        case RefType::__CONDITIONAL_COMPUTED_JUMP: return &RefTypes::CONDITIONAL_COMPUTED_JUMP;
        case RefType::__CONDITIONAL_COMPUTED_CALL: return &RefTypes::CONDITIONAL_COMPUTED_CALL;
        case RefType::__CONDITIONAL_CALL_TERMINATOR: return &RefTypes::CONDITIONAL_CALL_TERMINATOR;
        case RefType::__COMPUTED_CALL_TERMINATOR: return &RefTypes::COMPUTED_CALL_TERMINATOR;
        case RefType::__CALL_OVERRIDE_UNCONDITIONAL: return &RefTypes::CALL_OVERRIDE_UNCONDITIONAL;
        case RefType::__JUMP_OVERRIDE_UNCONDITIONAL: return &RefTypes::JUMP_OVERRIDE_UNCONDITIONAL;
        case RefType::__CALLOTHER_OVERRIDE_CALL: return &RefTypes::CALLOTHER_OVERRIDE_CALL;
        case RefType::__CALLOTHER_OVERRIDE_JUMP: return &RefTypes::CALLOTHER_OVERRIDE_JUMP;
        case RefType::__UNKNOWNDATA: return &RefTypes::DATA;
        case RefType::__READ: return &RefTypes::READ;
        case RefType::__WRITE: return &RefTypes::WRITE;
        case RefType::__READ_WRITE: return &RefTypes::READ_WRITE;
        case RefType::__READ_IND: return &RefTypes::READ_IND;
        case RefType::__WRITE_IND: return &RefTypes::WRITE_IND;
        case RefType::__READ_WRITE_IND: return &RefTypes::READ_WRITE_IND;
        case RefType::__UNKNOWNPARAM: return &RefTypes::PARAM;
        case RefType::__EXTERNAL_REF: return &RefTypes::EXTERNAL_REF;
        case RefType::__UNKNOWNDATA_IND: return &RefTypes::DATA_IND;
        case RefType::__DYNAMICDATA: return &RefTypes::THUNK;
    }
    return nullptr;
}

// Ghidra db "BinaryCodedField" data type codes (db.BinaryCodedField).
constexpr uint8_t BCF_BYTE_ARRAY = 0;
constexpr uint8_t BCF_SHORT_ARRAY = 3;
constexpr uint8_t BCF_INT_ARRAY = 4;
constexpr uint8_t BCF_LONG_ARRAY = 5;

// Sub memory block types (MemoryMapDBAdapterV3).
constexpr int SUB_TYPE_BUFFER = 2;
constexpr int SUB_TYPE_UNINITIALIZED = 3;
constexpr int SUB_TYPE_FILE_BYTES = 4;

// Symbol type ids (ghidra.program.model.symbol.SymbolType).
constexpr int SYMBOL_TYPE_LABEL = 0;
constexpr int SYMBOL_TYPE_LIBRARY = 1;
constexpr int SYMBOL_TYPE_NAMESPACE = 3;
constexpr int SYMBOL_TYPE_CLASS = 4;
constexpr int SYMBOL_TYPE_FUNCTION = 5;

// SourceType storage: bits 0-1 + bit 3 (SymbolDatabaseAdapter).
SourceType decodeSourceType(uint8_t flags) {
    switch (static_cast<unsigned>(((flags & 0x08) >> 1) | (flags & 0x03))) {
        case 1: return SourceType::ANALYSIS;
        case 2: return SourceType::USER_DEFINED;
        case 3: return SourceType::IMPORTED;
        case 4: return SourceType::USER_DEFINED_ADD;
        default: return SourceType::DEFAULT;
    }
}

// db.BinaryCodedField: [type][null-flag][big-endian payload]; int arrays
// store one zero byte then big-endian int32 values.
int64_t readIntArrayHead(const std::vector<uint8_t>& binary) {
    if (binary.size() < 6 || binary[0] != BCF_INT_ARRAY || binary[1] == 0xFF) {
        return -1;
    }
    int64_t v = 0;
    for (size_t i = 2; i < 6; ++i) {
        v = (v << 8) | binary[i];
    }
    return v;
}

/** Big-endian numeric field over an arbitrary byte region; advances off. */
int64_t readBeNum(const std::vector<uint8_t>& v, size_t& off, size_t n) {
    int64_t result = 0;
    for (size_t i = 0; i < n && off < v.size(); ++i) {
        result = (result << 8) | v[off++];
    }
    return result;
}

/** String field: int32 length (-1 = null) followed by bytes. */
std::string readBeString(const std::vector<uint8_t>& v, size_t& off) {
    if (off + 4 > v.size()) {
        return "";
    }
    int32_t len = 0;
    for (int i = 0; i < 4; ++i) {
        len = (len << 8) | v[off + i];
    }
    off += 4;
    if (len < 0) {
        return "";
    }
    size_t start = off;
    off += static_cast<size_t>(len);
    if (off > v.size()) {
        off = v.size();
        return "";
    }
    return std::string(reinterpret_cast<const char*>(v.data() + start),
                       static_cast<size_t>(len));
}

/** Binary field: int32 length (-1 = null) followed by bytes. */
std::vector<uint8_t> readBeBinary(const std::vector<uint8_t>& v, size_t& off) {
    if (off + 4 > v.size()) {
        return {};
    }
    int32_t len = 0;
    for (int i = 0; i < 4; ++i) {
        len = (len << 8) | v[off + i];
    }
    off += 4;
    if (len < 0) {
        return {};
    }
    size_t start = off;
    off += static_cast<size_t>(len);
    if (off > v.size()) {
        off = v.size();
        return {};
    }
    return std::vector<uint8_t>(v.begin() + static_cast<int64_t>(start),
                                v.begin() + static_cast<int64_t>(off));
}

/** Key of a long-keyed table as a signed int64. */
int64_t keyToLong(const std::vector<uint8_t>& key) {
    size_t off = 0;
    return readBeNum(key, off, key.size());
}

std::string toHexString(uint64_t v) {
    std::ostringstream oss;
    oss << std::hex << v;
    return oss.str();
}

}  // namespace

GzfProgramImporter::GzfProgramImporter(const GbfReader& reader) : reader_(reader) {}

std::unique_ptr<ProgramDB> GzfProgramImporter::import(const std::string& programName) {
    auto program = std::make_unique<ProgramDB>(programName, nullptr, nullptr);
    AddressFactory* factory = program->getAddressFactory();
    if (!factory->getDefaultAddressSpace()) {
        // Null-language construction registers no spaces; add a plain RAM
        // space so memory blocks and addresses resolve.  The factory keeps a
        // raw pointer (process-lifetime allocation, matching engine style).
        if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
            paf->addAddressSpace(
                new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 0));
        }
    }
    if (!factory || !factory->getDefaultAddressSpace()) {
        throw std::runtime_error("program has no default address space; cannot import");
    }

    // "Program" table: string key = attribute name, value = attribute value
    // (ProgramDBAdapter).  Restore the ones that drive later phases.
    if (const GbfTableSchema* t = reader_.findTable("Program")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            stats_.programRecords++;
            if ((t->keyTypeCode & 0x0F) != KEY_TYPE_STRING) {
                return;
            }
            std::string key(rec.key.begin(), rec.key.end());
            size_t off = 0;
            std::string value = readBeString(rec.data, off);
            if (key == "Language ID" && !value.empty()) {
                try {
                    program->setLanguageID(LanguageID(value));
                } catch (const std::invalid_argument&) {
                    // keep default empty id
                }
            } else if (key == "Compiler Spec ID" && !value.empty()) {
                program->setCompilerSpecID(CompilerSpecID(value));
            } else if (key == "Image Offset" || key == "Image Base") {
                // Ghidra 12 stores the preferred image base under "Image
                // Offset" as an UNPREFIXED HEX string (ProgramDB.java:
                // Long.toHexString / BigInteger(...,16)); legacy versions
                // used "Image Base" as a DECIMAL string.  Accept both.
                char* end = nullptr;
                const int base = (key == "Image Offset") ? 16 : 10;
                uint64_t imageBase = std::strtoull(value.c_str(), &end, base);
                if (end && *end == '\0' && imageBase != 0) {
                    auto* space =
                        const_cast<AddressSpace*>(factory->getDefaultAddressSpace());
                    const Address base(space, static_cast<int64_t>(imageBase));
                    program->setImageBase(base);
                    program->setEffectiveImageBase(base);
                    imageBase_ = static_cast<int64_t>(imageBase);
                }
            }
        });
    }

    std::map<int64_t, std::string> callingConventionsById;
    importPhase([&] { importCallingConventions(program.get(), callingConventionsById); },
                "calling conventions");
    importPhase([&] { importMemoryBlocks(program.get()); }, "memory blocks");
    // Original file bytes (for patched-binary export of imported programs).
    importPhase([&] { importFileBytes(); }, "file bytes");
    // Data types must precede instructions/functions/data: the corpus type ids
    // (2^56-tagged) are resolved through the importer's id map, and function
    // return types / data units reference them.
    importPhase([&] { importDataTypes(program.get(), callingConventionsById); },
                "data types");
    importPhase([&] { importInstructions(program.get()); }, "instructions");
    importPhase([&] { importSymbols(program.get()); }, "symbols");
    importPhase([&] { importFunctions(program.get(), callingConventionsById); },
                "functions");
    // Data before comments: comment records at data addresses attach to the
    // imported data units instead of fabricating 1-byte placeholders.
    importPhase([&] { importData(program.get()); }, "data");
    importPhase([&] { importComments(program.get()); }, "comments");
    importPhase([&] { importEquates(program.get()); }, "equates");
    importPhase([&] { importReferences(program.get()); }, "references");
    // Prototype decode contexts (ContextTable) are validated, and current
    // register values ("Range Map - Register_*") are restored into the
    // program context.
    importPhase([&] { importContextTable(program.get()); }, "context table");
    importPhase([&] { importRegisterValueMaps(program.get()); }, "register value maps");
    // P3i: bookmarks, relocations, the module tree (per Ghidra TreeManagerDB:
    // module/fragment tables, parent-child relationships and fragment address
    // ranges per tree), function bodies ("Range Map - SCOPE ADDRESSES") and
    // the program metadata key/value store.
    importPhase([&] { importBookmarks(program.get()); }, "bookmarks");
    importPhase([&] { importRelocations(program.get()); }, "relocations");
    importPhase([&] { importModuleTree(program.get()); }, "module tree");
    importPhase([&] { importFunctionScopes(program.get()); }, "function scopes");
    importPhase([&] { importFunctionTags(program.get()); }, "function tags");
    importPhase([&] { importEntryPoints(program.get()); }, "entry points");
    importPhase([&] { importCallFixups(program.get()); }, "call fixups");
    importPhase([&] { importVariables(program.get()); }, "function variables");
    importPhase([&] { importSourceMaps(program.get()); }, "source maps");
    importPhase([&] { importMetadata(program.get()); }, "metadata");

    return program;
}

void GzfProgramImporter::importPhase(const std::function<void()>& fn,
                                     const char* phaseName) {
    try {
        fn();
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("import phase '") + phaseName +
                                 "' failed: " + e.what());
    }
}

std::unique_ptr<Disassembler> GzfProgramImporter::makeDisassembler(ProgramDB* program) const {
    const std::string lang = program->getLanguageID().getIdAsString();
    std::string arch = "x86";
    int bitness = 32;
    if (lang.find("ARM") != std::string::npos || lang.find("arm") != std::string::npos) {
        arch = "arm";
    } else if (lang.find("MIPS") != std::string::npos) {
        arch = "mips";
    } else if (lang.find("PowerPC") != std::string::npos ||
               lang.find("PPC") != std::string::npos) {
        arch = "ppc";
    }
    if (lang.find("64") != std::string::npos) {
        bitness = 64;
    }
    auto dis = createDisassembler(arch, bitness, false);
    if (!dis) {
        throw std::runtime_error("failed to create disassembler for import");
    }
    dis->setProgram(program);
    return dis;
}

// ---------------------------------------------------------------------------
// Calling conventions: "Calling Conventions"
// ---------------------------------------------------------------------------

void GzfProgramImporter::importCallingConventions(
    ProgramDB* program, std::map<int64_t, std::string>& callingConventionsById) {
    const GbfTableSchema* cc = reader_.findTable("Calling Conventions");
    if (!cc) {
        return;
    }
    FunctionManager* mgr = program->getFunctionManager();
    // Byte key = convention id; data [Name].  Only user conventions are stored
    // (id >= 2); id 0 = unknown and id 1 = default are implicit in the adapter.
    reader_.visitRecords(*cc, [&](const GbfRecord& rec) {
        int64_t id = keyToLong(rec.key);
        size_t off = 0;
        std::string name = readBeString(rec.data, off);
        if (name.empty()) {
            return;
        }
        mgr->addCallingConvention(name,
                                  std::make_unique<PrototypeModel>(name, name, false));
        callingConventionsById[id] = name;
    });
}

// ---------------------------------------------------------------------------
// Data types: "Categories" + "Built-in datatypes" + "Composite Data Types" +
// "Component Data Types" + "Arrays" + "Typedefs" + "Pointers" +
// "Enumeration Data Types" + "Enumeration Values" + "Function Definitions" +
// "Function Parameters" + "DataTypeManager"
// ---------------------------------------------------------------------------

namespace {

// Datatype id spaces (Ghidra DataTypeDB): the top 8 bits select the table,
// the remaining 56 bits are the record ordinal within it.
constexpr int64_t DT_ID_COMPOSITE = 0x01;
constexpr int64_t DT_ID_COMPONENT = 0x02;
constexpr int64_t DT_ID_ARRAY = 0x03;
constexpr int64_t DT_ID_POINTER = 0x04;
constexpr int64_t DT_ID_TYPEDEF = 0x05;
constexpr int64_t DT_ID_FUNCTION_DEF = 0x06;
constexpr int64_t DT_ID_ENUM = 0x08;
constexpr int64_t DT_ID_BITFIELD = 0x09;
constexpr int64_t DT_ID_BUILTIN_BASE = 0;  // builtins use plain small ids

// BitFieldDBDataType id layout (top byte = DT_ID_BITFIELD): SS=bit size
// (bits 0-7), OO=bit offset (bits 8-15), BB=encoded base type (bits 16-23,
// kind in bits 5-6: 0=none,1=typedef,2=enum,3=builtin integer), TT=base
// datatype index (bits 24-55, excludes the kind byte).
constexpr int BITFIELD_SIZE_SHIFT = 0;
constexpr int BITFIELD_OFFSET_SHIFT = 8;
constexpr int BITFIELD_BASE_INFO_SHIFT = 16;
constexpr int BITFIELD_INDEX_SHIFT = 24;
constexpr int BITFIELD_BASE_KIND_NONE = 0;
constexpr int BITFIELD_BASE_KIND_TYPEDEF = 1;
constexpr int BITFIELD_BASE_KIND_ENUM = 2;
constexpr int BITFIELD_BASE_KIND_INTEGER = 3;
constexpr int64_t BITFIELD_INDEX_MASK = 0xFFFFFFFFLL;

// FunctionDefinitionDBAdapter flag bits.
constexpr uint8_t FUN_DEF_VARARG_FLAG = 0x1;
constexpr uint8_t FUN_DEF_NORETURN_FLAG = 0x2;

// FunctionDBAdapter flag bits (Function Data table).
constexpr uint8_t FUNC_INLINE_FLAG = 0x1;

// Calling convention ids stored in "Function Definitions": 0 = unknown,
// 1 = default (implicit), >= 2 = user convention from the table.
constexpr int64_t CALL_CONV_UNKNOWN = 0;
constexpr int64_t CALL_CONV_DEFAULT = 1;

}  // namespace

DataType* GzfProgramImporter::registerDataType(DataTypeManager* dtm, DataType* dt,
                                               int64_t id) {
    DataType* registered = nullptr;
    // addDataTypeWithId lives on DataTypeManagerImpl (ProgramDB's manager);
    // the corpus id space (2^56-tagged) cannot go through addDataType.
    if (auto* impl = dynamic_cast<DataTypeManagerImpl*>(dtm)) {
        registered = impl->addDataTypeWithId(dt, id);
    } else {
        warn("data type manager does not support explicit id registration");
        registered = dtm->addDataType(dt, nullptr);
    }
    datatypesById_[id] = registered;
    return registered;
}

DataType* GzfProgramImporter::resolveDataType(int64_t id) const {
    if (id == DataTypeManager::DEFAULT_DATATYPE_ID) {
        // Ghidra reserves datatype id 0 for DataType.DEFAULT ("undefined");
        // the builtin table never stores it.  Every reference with id 0
        // resolves to the default datatype, mirroring
        // DataTypeManagerDB.getDataType(0) (12.1.3 DWARF writes typedefs
        // with an unresolved base as id 0 instead of dropping them).
        return &DefaultDataType::dataType();
    }
    auto it = datatypesById_.find(id);
    return it != datatypesById_.end() ? it->second : nullptr;
}

CategoryPath GzfProgramImporter::categoryPathFor(DataTypeManager* dtm,
                                                 int64_t categoryId) const {
    auto it = datatypesById_.find(categoryId);
    if (it != datatypesById_.end() && it->second) {
        return it->second->getCategoryPath();
    }
    return CategoryPath::ROOT();
}

void GzfProgramImporter::importDataTypes(
    ProgramDB* program,
    const std::map<int64_t, std::string>& callingConventionsById) {
    DataTypeManager* dtm = program->getDataTypeManager();
    if (!dtm) {
        warn("program has no data type manager; datatypes skipped");
        return;
    }

    // DataTypeManager table (key = string): data organization settings.
    // Ghidra stores these under "dataOrg.<name>" keys (e.g.
    // "dataOrg.machine_alignment"); accept both prefixed and bare forms.
    if (const GbfTableSchema* t = reader_.findTable("DataTypeManager")) {
        DataOrganization* org = dtm->getDataOrganization();
        if (auto* impl = dynamic_cast<DataOrganizationImpl*>(org)) {
            reader_.visitRecords(*t, [&](const GbfRecord& rec) {
                std::string key(rec.key.begin(), rec.key.end());
                if (key.rfind("dataOrg.", 0) == 0) {
                    key = key.substr(std::strlen("dataOrg."));
                }
                size_t off = 0;
                std::string value = readBeString(rec.data, off);
                auto toInt = [](const std::string& s) {
                    char* end = nullptr;
                    long v = std::strtol(s.c_str(), &end, 10);
                    return (end && *end == '\0') ? static_cast<int>(v) : -1;
                };
                if (key == "pointer_size") {
                    int v = toInt(value);
                    if (v > 0) impl->setPointerSize(v);
                } else if (key == "machine_alignment") {
                    int v = toInt(value);
                    if (v > 0) impl->setMachineAlignment(v);
                } else if (key.rfind("size_alignment_map.", 0) == 0) {
                    int size = toInt(key.substr(std::strlen("size_alignment_map.")));
                    int alignment = toInt(value);
                    if (size > 0 && alignment > 0) impl->setSizeAlignment(size, alignment);
                } else if (key == "bitfield_packing.use_MS_convention" ||
                           key == "use_MS_convention") {
                    impl->setUseMSConvention(value == "true");
                }
                // "default_pointer_alignment" has no engine counterpart
                // (the engine derives it from the pointer size, matching the
                // Ghidra default); acknowledged here as non-representable.
            });
        }
    }

    // Categories: key = category id; data [Name][Parent ID].  Ids are small
    // ints (0 = root).  Categories are materialized lazily from the datatype
    // CategoryPath fields; the id table only drives path construction.
    std::vector<std::pair<int64_t, std::pair<std::string, int64_t>>> categoryRows;
    if (const GbfTableSchema* t = reader_.findTable("Categories")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            size_t off = 0;
            std::string name = readBeString(rec.data, off);
            int64_t parent = readBeNum(rec.data, off, 8);
            categoryRows.emplace_back(keyToLong(rec.key), std::make_pair(name, parent));
        });
    }
    std::map<int64_t, CategoryPath> categoryPaths;
    categoryPaths[0] = CategoryPath::ROOT();
    bool progress = true;
    while (progress) {
        progress = false;
        for (const auto& row : categoryRows) {
            if (categoryPaths.find(row.first) != categoryPaths.end()) {
                continue;
            }
            auto pit = categoryPaths.find(row.second.second);
            if (pit == categoryPaths.end()) {
                continue;
            }
            categoryPaths[row.first] = CategoryPath(pit->second, row.second.first);
            progress = true;
            stats_.categories++;
        }
    }
    for (const auto& row : categoryRows) {
        if (categoryPaths.find(row.first) == categoryPaths.end()) {
            warn("category id " + std::to_string(row.first) +
                 " has an unresolvable parent chain; skipped");
        }
    }
    auto categoryFor = [&](int64_t id) {
        auto it = categoryPaths.find(id);
        return it != categoryPaths.end() ? it->second : CategoryPath::ROOT();
    };

    // Built-in datatypes: key = datatype id; data [Name][Class Name][Category
    // ID].  Corpus ids are small (100..131 in the PE corpora); the engine
    // pre-registers equivalent primitive types under its own small ids, so
    // name-matched engine types are aliased to the corpus ids.
    auto makeBuiltIn = [&](const std::string& className, DataTypeManager* mgr)
        -> DataType* {
        // Class name last segment -> engine class (nullptr = placeholder).
        std::string cls = className;
        auto dot = cls.rfind('.');
        if (dot != std::string::npos) {
            cls = cls.substr(dot + 1);
        }
        if (cls == "CharDataType") return new CharDataType(mgr);
        if (cls == "WordDataType") return new WordDataType(mgr);
        if (cls == "DWordDataType") return new DWordDataType(mgr);
        if (cls == "ByteDataType") return new ByteDataType(mgr);
        if (cls == "QWordDataType") return new QWordDataType(mgr);
        if (cls == "IBO32DataType") return new IBO32DataType(mgr);
        if (cls == "IBO64DataType") return new IBO64DataType(mgr);
        if (cls == "UnsignedIntegerDataType") return new UnsignedIntegerDataType(mgr);
        if (cls == "IntegerDataType") return new IntegerDataType(mgr);
        if (cls == "VoidDataType") return new VoidDataType(mgr);
        if (cls == "UnsignedCharDataType") return new UnsignedCharDataType(mgr);
        if (cls == "WideChar16DataType") return new WideChar16DataType(mgr);
        if (cls == "UnsignedShortDataType") return new UnsignedShortDataType(mgr);
        if (cls == "Undefined4DataType") return new Undefined4DataType(mgr);
        if (cls == "Undefined8DataType") return new Undefined8DataType(mgr);
        if (cls == "Undefined1DataType") return new Undefined1DataType(mgr);
        if (cls == "Undefined2DataType") return new Undefined2DataType(mgr);
        if (cls == "UnsignedLongDataType") return new UnsignedLongDataType(mgr);
        if (cls == "WideCharDataType") return new WideCharDataType(mgr);
        if (cls == "UnsignedLongLongDataType") return new UnsignedLongLongDataType(mgr);
        if (cls == "LongDataType") return new LongDataType(mgr);
        if (cls == "LongLongDataType") return new LongLongDataType(mgr);
        if (cls == "ShortDataType") return new ShortDataType(mgr);
        if (cls == "BooleanDataType") return new BooleanDataType(mgr);
        if (cls == "FloatDataType") return new FloatDataType(mgr);
        if (cls == "Float16DataType") return new Float16DataType(mgr);
        // Ghidra's signed size-alias builtins map onto the engine's signed
        // integer classes (same width/semantics).
        if (cls == "Float2DataType") return new Float16DataType(mgr);
        if (cls == "Float4DataType") return new FloatDataType(mgr);
        if (cls == "Integer16DataType") return new ShortDataType(mgr);
        if (cls == "UnsignedInteger16DataType") return new UnsignedShortDataType(mgr);
        if (cls == "WideChar32DataType") {
            stats_.builtinPlaceholders++;
            return new PlaceholderDataType(mgr, "wchar32", 4);
        }
        if (cls == "SignedDWordDataType") return new IntegerDataType(mgr);
        if (cls == "SignedQWordDataType") return new LongLongDataType(mgr);
        if (cls == "SignedWordDataType") return new ShortDataType(mgr);
        if (cls == "UnicodeDataType") return new UnicodeDataType(mgr);
        if (cls == "TerminatedStringDataType") return new TerminatedStringDataType(mgr);
        if (cls == "TerminatedUnicodeDataType") return new TerminatedUnicodeDataType(mgr);
        if (cls == "StringDataType") return new StringDataType(mgr);
        // Engine placeholders for classes it does not implement:
        // GuidDataType is fixed at 16 bytes; the PE dynamic types are resolved
        // per data unit by scanning memory.
        if (cls == "GuidDataType") {
            stats_.builtinPlaceholders++;
            return new PlaceholderDataType(mgr, "GUID", 16);
        }
        if (cls == "PEx64UnwindInfoDataType" || cls == "PERichTableDataType" ||
            cls == "MUIResourceDataType") {
            stats_.builtinPlaceholders++;
            return new PlaceholderDataType(mgr, cls, 1);
        }
        warn("builtin class '" + className + "' is not implemented by the engine");
        stats_.builtinPlaceholders++;
        return new PlaceholderDataType(mgr, cls, 1);
    };

    if (const GbfTableSchema* t = reader_.findTable("Built-in datatypes")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            int64_t id = keyToLong(rec.key);
            size_t off = 0;
            std::string name = readBeString(rec.data, off);
            std::string className = readBeString(rec.data, off);
            int64_t categoryId = readBeNum(rec.data, off, 8);
            (void)categoryId;  // builtins live in the root category
            // Name-matched engine builtin (e.g. "int"): alias the corpus id
            // to the existing instance instead of duplicating the path.
            DataType* existing = dtm->getDataType(CategoryPath::ROOT(), name);
            if (existing) {
                registerDataType(dtm, existing, id);
                stats_.builtinAliased++;
                return;
            }
            DataType* dt = makeBuiltIn(className, dtm);
            if (dt) {
                registerDataType(dtm, dt, id);
                if (dynamic_cast<PlaceholderDataType*>(dt) == nullptr) {
                    stats_.builtins++;
                }
            }
        });
    }

    // Composite shells: key = datatype id; data [Name][Comment][Is Union]
    // [Category ID][Length][Alignment][Number Of Components][Source Archive
    // ID][Source Data Type ID][Source Sync Time][Last Change Time][Pack]
    // [MinAlign].  Components fill the shells afterwards.
    if (const GbfTableSchema* t = reader_.findTable("Composite Data Types")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            int64_t id = keyToLong(rec.key);
            size_t off = 0;
            PendingComposite pc;
            pc.id = id;
            std::string name = readBeString(rec.data, off);
            std::string comment = readBeString(rec.data, off);
            pc.isUnion = readBeNum(rec.data, off, 1) != 0;
            pc.categoryId = readBeNum(rec.data, off, 8);
            pc.length = static_cast<int>(readBeNum(rec.data, off, 4));
            readBeNum(rec.data, off, 4);  // alignment (repack hint: derived
                                          // from min align + data org; not
                                          // stored independently)
            readBeNum(rec.data, off, 4);  // number of components
            readBeNum(rec.data, off, 8);  // source archive id
            readBeNum(rec.data, off, 8);  // source datatype id
            readBeNum(rec.data, off, 8);  // source sync time
            readBeNum(rec.data, off, 8);  // last change time
            pc.pack = static_cast<int>(readBeNum(rec.data, off, 4));
            pc.minAlignment = static_cast<int>(readBeNum(rec.data, off, 4));

            CategoryPath path = categoryFor(pc.categoryId);
            DataType* shell = nullptr;
            if (pc.isUnion) {
                shell = new UnionDataType(path, name, dtm);
            } else {
                shell = new StructureDataType(path, name, pc.length, dtm);
            }
            if (auto* comp = dynamic_cast<Composite*>(shell)) {
                // Ghidra's PACK column: -1 = not packed, 0 = packed with the
                // default value, >0 = explicit packing value.
                if (pc.pack == 0) {
                    comp->setPackingEnabled(true);
                } else if (pc.pack > 0) {
                    comp->setExplicitPackingValue(pc.pack);
                }
                if (pc.minAlignment > 0) {
                    comp->setExplicitMinimumAlignment(pc.minAlignment);
                }
            }
            pc.name = name;
            pc.comment = comment;
            pendingComposites_[id] = pc;
            registerDataType(dtm, shell, id);
            stats_.composites++;
        });
    }

    // Enumeration data types: key = datatype id; data [Name][Comment][Category
    // ID][Size][Source Archive ID][Source Data Type ID][Sync][Change].
    if (const GbfTableSchema* t = reader_.findTable("Enumeration Data Types")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            int64_t id = keyToLong(rec.key);
            size_t off = 0;
            std::string name = readBeString(rec.data, off);
            std::string comment = readBeString(rec.data, off);
            int64_t categoryId = readBeNum(rec.data, off, 8);
            int size = static_cast<int>(readBeNum(rec.data, off, 1));
            readBeNum(rec.data, off, 8);  // source archive id
            readBeNum(rec.data, off, 8);  // source datatype id
            readBeNum(rec.data, off, 8);  // sync
            readBeNum(rec.data, off, 8);  // change
            auto* e = new EnumDataType(categoryFor(categoryId), name, size, dtm);
            if (!comment.empty()) e->setDescription(comment);
            registerDataType(dtm, e, id);
            stats_.enums++;
        });
    }

    // Function definitions (shells; parameters/return types resolve later).
    struct PendingFunctionDef {
        int64_t id = 0;
        int64_t returnTypeId = 0;
        FunctionDefinitionDataType* dt = nullptr;
    };
    std::vector<PendingFunctionDef> pendingFunctionDefs;
    if (const GbfTableSchema* t = reader_.findTable("Function Definitions")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            int64_t id = keyToLong(rec.key);
            size_t off = 0;
            std::string name = readBeString(rec.data, off);
            std::string comment = readBeString(rec.data, off);
            int64_t categoryId = readBeNum(rec.data, off, 8);
            int64_t returnTypeId = readBeNum(rec.data, off, 8);
            uint8_t flags = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
            int64_t callConvId = readBeNum(rec.data, off, 1);
            readBeNum(rec.data, off, 8);  // source archive id
            readBeNum(rec.data, off, 8);  // source datatype id
            readBeNum(rec.data, off, 8);  // sync
            readBeNum(rec.data, off, 8);  // change

            auto* f = new FunctionDefinitionDataType(categoryFor(categoryId), name, nullptr,
                                                     dtm);
            f->setComment(comment);
            if (flags & FUN_DEF_VARARG_FLAG) {
                f->setVarArgs(true);
            }
            if (flags & FUN_DEF_NORETURN_FLAG) {
                f->setNoReturn(true);
            }
            if (callConvId == CALL_CONV_DEFAULT) {
                f->setCallingConvention("default");
            } else if (callConvId >= 2) {
                auto cit = callingConventionsById.find(callConvId);
                if (cit != callingConventionsById.end()) {
                    f->setCallingConvention(cit->second);
                }
            }
            pendingFunctionDefs.push_back(
                PendingFunctionDef{id, returnTypeId, f});
            registerDataType(dtm, f, id);
            stats_.functionDefs++;
        });
    }

    // Pointers: key = datatype id; data [Data Type ID][Category ID][Length].
    // Typedefs/arrays/pointers reference each other freely, so all three are
    // collected and resolved together in a fixpoint loop.
    if (const GbfTableSchema* t = reader_.findTable("Pointers")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            PendingPointer pp;
            pp.id = keyToLong(rec.key);
            size_t off = 0;
            pp.baseId = readBeNum(rec.data, off, 8);
            pp.categoryId = readBeNum(rec.data, off, 8);
            // Ghidra stores the pointer Length as a signed byte: -1 (0xFF)
            // means "language default pointer size", so the raw byte must be
            // sign-extended, not read unsigned (255 would become a 255-byte
            // pointer with a "*2040" name).
            pp.length = static_cast<int>(static_cast<int8_t>(readBeNum(rec.data, off, 1)));
            pendingPointers_.push_back(pp);
        });
    }

    // Typedefs: key = datatype id; data [Data Type ID][Flags][Name][Category
    // ID][Source Archive ID][Universal Data Type ID][Sync][Change].
    if (const GbfTableSchema* t = reader_.findTable("Typedefs")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            size_t off = 0;
            PendingTypedef pt;
            pt.id = keyToLong(rec.key);
            pt.baseId = readBeNum(rec.data, off, 8);
            readBeNum(rec.data, off, 2);  // flags
            pt.name = readBeString(rec.data, off);
            pt.categoryId = readBeNum(rec.data, off, 8);
            readBeNum(rec.data, off, 8);  // source archive id
            readBeNum(rec.data, off, 8);  // universal datatype id
            readBeNum(rec.data, off, 8);  // sync
            readBeNum(rec.data, off, 8);  // change
            pendingTypedefs_.push_back(pt);
        });
    }

    // Arrays: key = datatype id; data [Data Type ID][Dimension][Length]
    // [Category ID].  Length = element length; -1 derives from the element.
    if (const GbfTableSchema* t = reader_.findTable("Arrays")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            PendingArray pa;
            pa.id = keyToLong(rec.key);
            size_t off = 0;
            pa.baseId = readBeNum(rec.data, off, 8);
            pa.dimension = static_cast<int>(readBeNum(rec.data, off, 4));
            pa.elementLength = static_cast<int>(readBeNum(rec.data, off, 4));
            pa.categoryId = readBeNum(rec.data, off, 8);
            pendingArrays_.push_back(pa);
        });
    }
    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (auto it = pendingPointers_.begin(); it != pendingPointers_.end();) {
            if (resolveDataType(it->id) != nullptr) {
                ++it;
                continue;
            }
            DataType* base = resolveDataType(it->baseId);
            if (!base && it->baseId < 0) {
                // Negative base ids (Ghidra NULL/BAD datatype ids) denote
                // pointers whose target never resolved in Ghidra; they
                // surface as void pointers with the corpus length (or the
                // default pointer size when unset).  Base id 0 resolves to
                // the default datatype ("undefined *") in resolveDataType.
                base = resolveDataType(117);  // corpus "void"
                if (!base) {
                    base = dtm->getDataType(CategoryPath::ROOT(), "void");
                }
            }
            if (!base) {
                ++it;
                continue;
            }
            DataType* dt = new PointerDataType(base, it->length, dtm);
            registerDataType(dtm, dt, it->id);
            stats_.pointers++;
            progressed = true;
            it = pendingPointers_.erase(it);
        }
        for (auto it = pendingTypedefs_.begin(); it != pendingTypedefs_.end();) {
            if (resolveDataType(it->id) != nullptr) {
                ++it;
                continue;
            }
            DataType* base = resolveDataType(it->baseId);
            if (!base) {
                ++it;
                continue;
            }
            auto* td = new TypedefDataType(categoryFor(it->categoryId), it->name, base,
                                           dtm);
            registerDataType(dtm, td, it->id);
            stats_.typedefs++;
            progressed = true;
            it = pendingTypedefs_.erase(it);
        }
        for (auto it = pendingArrays_.begin(); it != pendingArrays_.end();) {
            if (resolveDataType(it->id) != nullptr) {
                ++it;
                continue;
            }
            DataType* base = resolveDataType(it->baseId);
            if (!base) {
                ++it;
                continue;
            }
            DataType* dt = new ArrayDataType(base, it->dimension, it->elementLength,
                                             dtm, /*ownsDataType=*/false);
            registerDataType(dtm, dt, it->id);
            stats_.arrays++;
            progressed = true;
            it = pendingArrays_.erase(it);
        }
    }
    for (const PendingPointer& pp : pendingPointers_) {
        stats_.datatypeUnresolvedRefs++;
        warn("pointer id " + std::to_string(pp.id) + " base type " +
             std::to_string(pp.baseId) + " unresolved; skipped");
    }
    for (const PendingTypedef& pt : pendingTypedefs_) {
        stats_.datatypeUnresolvedRefs++;
        warn("typedef '" + pt.name + "' base type " + std::to_string(pt.baseId) +
             " unresolved; skipped");
    }
    for (const PendingArray& pa : pendingArrays_) {
        stats_.datatypeUnresolvedRefs++;
        warn("array id " + std::to_string(pa.id) + " element type " +
             std::to_string(pa.baseId) + " unresolved; skipped");
    }
    pendingPointers_.clear();
    pendingTypedefs_.clear();
    pendingArrays_.clear();

    // Enumeration values: key = value id; data [Name][Value][Enum ID][Comment].
    if (const GbfTableSchema* t = reader_.findTable("Enumeration Values")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            size_t off = 0;
            PendingEnumValue ev;
            ev.name = readBeString(rec.data, off);
            ev.value = readBeNum(rec.data, off, 8);
            ev.enumId = readBeNum(rec.data, off, 8);
            ev.comment = readBeString(rec.data, off);
            pendingEnumValues_.push_back(ev);
        });
    }

    // Function parameters: key = parameter id; data [Parent ID][Data Type ID]
    // [Name][Comment][Ordinal][Data Type Length].
    if (const GbfTableSchema* t = reader_.findTable("Function Parameters")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            size_t off = 0;
            PendingFunctionParam fp;
            fp.parent = readBeNum(rec.data, off, 8);
            fp.dtId = readBeNum(rec.data, off, 8);
            fp.name = readBeString(rec.data, off);
            fp.comment = readBeString(rec.data, off);
            fp.ordinal = static_cast<int>(readBeNum(rec.data, off, 4));
            readBeNum(rec.data, off, 4);  // data type length (derived)
            pendingFunctionParams_.push_back(fp);
        });
    }

    // Component Data Types: key = component id; data [Parent ID][Offset][Data
    // Type ID][Field Name][Comment][Component Size][Ordinal].  Structures are
    // packed (running-sum offsets in both Ghidra and the engine); each
    // component's computed offset is verified against the corpus.
    if (const GbfTableSchema* t = reader_.findTable("Component Data Types")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            size_t off = 0;
            PendingComponent comp;
            comp.parent = readBeNum(rec.data, off, 8);
            comp.offset = static_cast<int>(readBeNum(rec.data, off, 4));
            comp.dtId = readBeNum(rec.data, off, 8);
            comp.name = readBeString(rec.data, off);
            comp.comment = readBeString(rec.data, off);
            comp.size = static_cast<int>(readBeNum(rec.data, off, 4));
            comp.ordinal = static_cast<int>(readBeNum(rec.data, off, 4));
            pendingComponents_.push_back(comp);
            stats_.components++;
        });
    }
    std::sort(pendingComponents_.begin(), pendingComponents_.end(),
              [](const PendingComponent& a, const PendingComponent& b) {
                  if (a.parent != b.parent) return a.parent < b.parent;
                  return a.ordinal < b.ordinal;
              });
    for (const PendingComponent& comp : pendingComponents_) {
        DataType* parent = resolveDataType(comp.parent);
        if (!parent) {
            stats_.datatypeUnresolvedRefs++;
            warn("component parent id " + std::to_string(comp.parent) +
                 " unresolved; skipped");
            continue;
        }
        // Bit-field components carry an encoded datatype id (kind 9) whose low
        // 56 bits hold the base datatype index, bit size and bit offset (see
        // BitFieldDBDataType.getId()/getBitFieldDataType()).
        bool isBitField = (comp.dtId >> 56) == DT_ID_BITFIELD;
        DataType* compDt = nullptr;
        int bitFieldBitSize = 0;
        int bitFieldBitOffset = 0;
        if (isBitField) {
            bitFieldBitSize = static_cast<int>(
                (comp.dtId >> BITFIELD_SIZE_SHIFT) & 0xFF);
            bitFieldBitOffset = static_cast<int>(
                (comp.dtId >> BITFIELD_OFFSET_SHIFT) & 0xFF);
            int baseTypeInfo = static_cast<int>(
                (comp.dtId >> BITFIELD_BASE_INFO_SHIFT) & 0xFF);
            int baseKind = (baseTypeInfo >> 5) & 3;
            int64_t baseIndex = (comp.dtId >> BITFIELD_INDEX_SHIFT) &
                                BITFIELD_INDEX_MASK;
            if (baseKind == BITFIELD_BASE_KIND_TYPEDEF) {
                compDt = resolveDataType((DT_ID_TYPEDEF << 56) | baseIndex);
            } else if (baseKind == BITFIELD_BASE_KIND_ENUM) {
                compDt = resolveDataType((DT_ID_ENUM << 56) | baseIndex);
            } else if (baseKind == BITFIELD_BASE_KIND_INTEGER) {
                compDt = resolveDataType(baseIndex);
            }
            if (!compDt) {
                // Ghidra falls back to IntegerDataType when the encoded base
                // cannot be resolved.
                compDt = resolveDataType(116);  // corpus "int"
                if (!compDt) {
                    compDt = dtm->getDataType(CategoryPath::ROOT(), "int");
                }
            }
        } else {
            compDt = resolveDataType(comp.dtId);
        }
        if (!compDt) {
            stats_.datatypeUnresolvedRefs++;
            warn("component id " + std::to_string(comp.dtId) + " unresolved in parent '" +
                 parent->getName() + "'; skipped");
            continue;
        }
        auto* structure = dynamic_cast<Structure*>(parent);
        auto* uni = dynamic_cast<Union*>(parent);
        if (structure) {
            // Insert at the corpus byte offset: aligned structures carry
            // padding between components that running-sum packing cannot
            // reproduce.  The engine's insertAtOffset places components at the
            // exact offset, matching Ghidra's stored layout.  Bit-field
            // components go through insertBitFieldAt so that fields sharing
            // one storage unit keep their corpus offsets.
            if (isBitField) {
                structure->insertBitFieldAt(comp.offset, comp.size, bitFieldBitOffset,
                                            compDt, bitFieldBitSize, comp.name,
                                            comp.comment);
            } else {
                structure->insertAtOffset(comp.offset, compDt, comp.size, comp.name,
                                          comp.comment);
            }
            DataTypeComponent* dc = structure->getComponent(comp.ordinal);
            if (dc && dc->getOffset() != comp.offset) {
                stats_.componentOffsetMismatches++;
                warn("structure '" + parent->getName() + "' component '" + comp.name +
                     "' offset " + std::to_string(dc->getOffset()) + " != corpus " +
                     std::to_string(comp.offset));
            }
        } else if (uni) {
            if (isBitField) {
                auto* bf = new BitFieldDataType(compDt, bitFieldBitSize,
                                                bitFieldBitOffset);
                DataTypeComponent* dc =
                    uni->insert(comp.ordinal, bf, comp.size, comp.name, comp.comment);
                if (auto* concrete = dynamic_cast<DataTypeComponentImpl*>(dc)) {
                    concrete->setOwnsDataType(true);
                }
            } else {
                uni->insert(comp.ordinal, compDt, comp.size, comp.name, comp.comment);
            }
            if (comp.offset != 0) {
                stats_.componentOffsetMismatches++;
                warn("union '" + parent->getName() + "' component '" + comp.name +
                     "' has non-zero corpus offset " + std::to_string(comp.offset));
            }
        } else {
            stats_.datatypeUnresolvedRefs++;
            warn("component parent id " + std::to_string(comp.parent) +
                 " is not a composite; skipped");
        }
    }
    // Final lengths: structures take the corpus length (padding after the last
    // defined component); unions are the max component extent (verified).
    for (const auto& entry : pendingComposites_) {
        const PendingComposite& pc = entry.second;
        if (auto* structure = dynamic_cast<Structure*>(resolveDataType(pc.id))) {
            structure->setLength(pc.length);
            if (!pc.comment.empty()) structure->setDescription(pc.comment);
        } else if (auto* uni = dynamic_cast<Union*>(resolveDataType(pc.id))) {
            if (uni->getLength() != pc.length) {
                stats_.componentOffsetMismatches++;
                warn("union '" + pc.name + "' length " +
                     std::to_string(uni->getLength()) + " != corpus " +
                     std::to_string(pc.length));
            }
            if (!pc.comment.empty()) uni->setDescription(pc.comment);
        }
    }

    // Enum values (after enums exist; names unique per enum).
    for (const PendingEnumValue& ev : pendingEnumValues_) {
        auto* e = dynamic_cast<EnumDataType*>(resolveDataType(ev.enumId));
        if (!e) {
            stats_.datatypeUnresolvedRefs++;
            warn("enum value '" + ev.name + "' parent enum " +
                 std::to_string(ev.enumId) + " unresolved; skipped");
            continue;
        }
        e->add(ev.name, ev.value, ev.comment);
        stats_.enumValues++;
    }
    pendingEnumValues_.clear();

    // Function parameters (collected per function, in ordinal order) and
    // deferred return types.
    std::map<int64_t, std::vector<ParameterDefinition*>> paramsByFunction;
    for (const PendingFunctionParam& fp : pendingFunctionParams_) {
        auto* f = dynamic_cast<FunctionDefinitionDataType*>(resolveDataType(fp.parent));
        if (!f) {
            stats_.datatypeUnresolvedRefs++;
            warn("function parameter parent id " + std::to_string(fp.parent) +
                 " unresolved; skipped");
            continue;
        }
        DataType* pdt = resolveDataType(fp.dtId);
        if (!pdt) {
            stats_.datatypeUnresolvedRefs++;
            warn("function parameter '" + fp.name + "' datatype " +
                 std::to_string(fp.dtId) + " unresolved; skipped");
            continue;
        }
        paramsByFunction[fp.parent].push_back(
            new ParameterDefinitionImpl(fp.name, pdt, fp.comment, fp.ordinal));
        stats_.functionParams++;
    }
    for (auto& entry : paramsByFunction) {
        auto& params = entry.second;
        std::sort(params.begin(), params.end(),
                  [](const ParameterDefinition* a, const ParameterDefinition* b) {
                      return a->getOrdinal() < b->getOrdinal();
                  });
        auto* f = dynamic_cast<FunctionDefinitionDataType*>(resolveDataType(entry.first));
        if (f) {
            f->setArguments(params);
        }
    }
    pendingFunctionParams_.clear();

    for (const PendingFunctionDef& fd : pendingFunctionDefs) {
        if (fd.returnTypeId <= 0) {
            continue;
        }
        DataType* ret = resolveDataType(fd.returnTypeId);
        if (!ret) {
            stats_.datatypeUnresolvedRefs++;
            warn("function definition '" + fd.dt->getName() + "' return type " +
                 std::to_string(fd.returnTypeId) + " unresolved; skipped");
            continue;
        }
        fd.dt->setReturnType(ret);
    }
}

// ---------------------------------------------------------------------------
// Memory blocks: "Memory Blocks" + "Sub Memory Blocks" + "File Bytes"
// ---------------------------------------------------------------------------

void GzfProgramImporter::importFileBytes() {
    const GbfTableSchema* t = reader_.findTable("File Bytes");
    if (!t) {
        return;
    }
    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        if (!originalFileBytes_.empty()) {
            return;
        }
        // Record layout (all data columns; the record key is empty):
        //   [string Filename][long Offset][long Size]
        //   [binary Chain Buffer IDs][binary Layered Chain Buffer IDs]
        size_t off = 0;
        std::string filename = readBeString(rec.data, off);
        int64_t fileOffset = readBeNum(rec.data, off, 8);
        int64_t fileSize = readBeNum(rec.data, off, 8);
        std::vector<uint8_t> bufferIds = readBeBinary(rec.data, off);
        if (bufferIds.empty()) {
            return;
        }
        // The chain id is the trailing 4-byte big-endian value in the blob
        // (the blob may carry extra encoding bytes depending on Ghidra
        // version; the id is always the last 4 bytes).
        int64_t chainId = 0;
        const size_t n = bufferIds.size();
        for (size_t i = n > 4 ? n - 4 : 0; i < n; ++i) {
            chainId = (chainId << 8) | bufferIds[i];
        }
        std::vector<uint8_t> bytes = reader_.readChainedBuffer(static_cast<int32_t>(chainId));
        if (fileSize > 0 && bytes.size() >= static_cast<size_t>(fileSize)) {
            bytes.resize(static_cast<size_t>(fileSize));
        }
        if (bytes.empty()) {
            return;
        }
        originalFileName_ = filename;
        originalFileBytes_ = std::move(bytes);
        stats_.fileBytesRestored = static_cast<int>(originalFileBytes_.size());
        (void)fileOffset;
    });
    if (originalFileBytes_.empty()) {
        warn("File Bytes table is empty or unreadable; exporting a patched "
             "binary from this import will not be available");
    }
}

void GzfProgramImporter::importMemoryBlocks(ProgramDB* program) {
    DefaultMemory* dmem = dynamic_cast<DefaultMemory*>(program->getMemory());
    if (!dmem) {
        warn("memory backend is not DefaultMemory");
        return;
    }
    // Established pattern: the factory hands out a const space view but
    // Address requires a mutable pointer (see DisassemblyAnalyzer).
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());

    const GbfTableSchema* blockschema = reader_.findTable("Memory Blocks");
    const GbfTableSchema* subschema = reader_.findTable("Sub Memory Blocks");
    if (!blockschema || !subschema) {
        warn("missing memory map tables; memory import skipped");
        return;
    }

    // FileBytes: data [Filename][Offset][Size][Chain ids][Layered]; the chain
    // ids are int-array BinaryCodedFields whose first value is the head buffer
    // id that completes the file's bytes.
    std::map<int64_t, int64_t> fileBytesChain;  // fileBytesId -> head buffer id
    if (const GbfTableSchema* fileschema = reader_.findTable("File Bytes")) {
        reader_.visitRecords(*fileschema, [&](const GbfRecord& rec) {
            stats_.fileBytes++;
            size_t off = 0;
            readBeString(rec.data, off);  // filename
            readBeNum(rec.data, off, 8);  // file offset
            readBeNum(rec.data, off, 8);  // size
            std::vector<uint8_t> chain = readBeBinary(rec.data, off);
            std::vector<uint8_t> layered = readBeBinary(rec.data, off);
            int64_t head = readIntArrayHead(chain);
            if (head < 0) {
                head = readIntArrayHead(layered);
            }
            int64_t fileId = keyToLong(rec.key);
            if (head >= 0) {
                fileBytesChain[fileId] = head;
            } else {
                warn("file bytes id " + std::to_string(fileId) + " has no buffer chain");
            }
        });
    }

    // Sub blocks: key = sub id; data [Parent ID][Type][Length][Starting Offset]
    // [Source ID][Source Address/Offset]
    struct SubBlock {
        int64_t parent = 0;
        int type = 0;
        int64_t length = 0;
        int64_t startOffset = 0;
        int64_t sourceId = 0;
        int64_t sourceAddrOffset = 0;
    };
    std::vector<SubBlock> subBlocks;
    reader_.visitRecords(*subschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        SubBlock sb;
        sb.parent = readBeNum(rec.data, off, 8);
        sb.type = static_cast<int>(readBeNum(rec.data, off, 1));
        sb.length = readBeNum(rec.data, off, 8);
        sb.startOffset = readBeNum(rec.data, off, 8);
        sb.sourceId = readBeNum(rec.data, off, 4);
        sb.sourceAddrOffset = readBeNum(rec.data, off, 8);
        subBlocks.push_back(sb);
        stats_.subMemoryBlocks++;
    });

    // Memory blocks: data [Name][Comments][Source Name][Flags][Start Address]
    // [Length][Segment].  Flags follow ghidra MemoryBlock: EXECUTE=1, WRITE=2,
    // READ=4, VOLATILE=8, ... Start Address is an address-map key whose low 32
    // bits are the image offset in the default (code) space (base index 0).
    reader_.visitRecords(*blockschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        std::string name = readBeString(rec.data, off);
        std::string comments = readBeString(rec.data, off);
        std::string sourceName = readBeString(rec.data, off);
        uint8_t flags = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
        uint64_t imageOffset = static_cast<uint64_t>(readBeNum(rec.data, off, 8)) &
                               0xFFFFFFFFull;
        int64_t length = readBeNum(rec.data, off, 8);
        readBeNum(rec.data, off, 4);  // segment

        Address start = imageAddress(space, imageOffset);
        DefaultMemoryBlock* block =
            dmem->createInitializedBlock(name, start, length, 0, /*overlay=*/false);
        if (!block) {
            warn("failed to create memory block '" + name + "'");
            return;
        }
        block->setComment(comments);
        block->setSourceName(sourceName);
        block->setRead((flags & 0x4) != 0);
        block->setWrite((flags & 0x2) != 0);
        block->setExecute((flags & 0x1) != 0);
        stats_.memoryBlocks++;
        // Populate contents even for read-only blocks (creates require write).
        const bool hadWrite = block->isWrite();
        if (!hadWrite) {
            block->setWrite(true);
        }

        int64_t blockId = keyToLong(rec.key);
        for (const SubBlock& sb : subBlocks) {
            if (sb.parent != blockId) {
                continue;
            }
            Address dst = imageAddress(space, imageOffset + static_cast<uint64_t>(sb.startOffset));
            if (sb.type == SUB_TYPE_BUFFER) {
                // Source ID = DBBuffer id of the sub-buffer chain
                std::vector<uint8_t> buf =
                    reader_.readChainedBuffer(static_cast<int32_t>(sb.sourceId));
                size_t n = std::min<size_t>(buf.size(), static_cast<size_t>(sb.length));
                if (n > 0) {
                    block->putBytes(dst, buf.data(), static_cast<int>(n));
                }
            } else if (sb.type == SUB_TYPE_FILE_BYTES) {
                // Source ID = FileBytes id; Source Address/Offset = file offset
                auto it = fileBytesChain.find(sb.sourceId);
                if (it == fileBytesChain.end()) {
                    warn("file bytes id " + std::to_string(sb.sourceId) +
                         " has no chain for block '" + name + "'");
                    continue;
                }
                std::vector<uint8_t> fb =
                    reader_.readChainedBuffer(static_cast<int32_t>(it->second));
                uint64_t fno = static_cast<uint64_t>(sb.sourceAddrOffset) & 0xFFFFFFFFull;
                if (fno > fb.size()) {
                    warn("file bytes range out of bounds for block '" + name + "'");
                    continue;
                }
                size_t n = std::min<size_t>(fb.size() - fno, static_cast<size_t>(sb.length));
                if (n > 0) {
                    block->putBytes(dst, fb.data() + fno, static_cast<int>(n));
                }
            }
            // UNINITIALIZED (and mapped) types: leave the zero-filled block.
        }
        if (!hadWrite) {
            block->setWrite(false);
        }
    });
}

// ---------------------------------------------------------------------------
// Instructions: "Prototypes" + "Instructions"
// ---------------------------------------------------------------------------

void GzfProgramImporter::importInstructions(ProgramDB* program) {
    const GbfTableSchema* protoschema = reader_.findTable("Prototypes");
    const GbfTableSchema* instschema = reader_.findTable("Instructions");
    if (!protoschema) {
        warn("missing 'Prototypes' table; instructions skipped");
        return;
    }
    if (!instschema) {
        warn("missing 'Instructions' table; instructions skipped");
        return;
    }
    Listing* listing = program->getListing();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!listing || !space) {
        warn("no listing / address factory; instructions skipped");
        return;
    }

    // Prototypes: key = proto id; data [Bytes][Address][InDelaySlot]
    std::map<int32_t, std::vector<uint8_t>> protos;
    reader_.visitRecords(*protoschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        std::vector<uint8_t> bytes = readBeBinary(rec.data, off);
        readBeNum(rec.data, off, 8);  // address (context)
        readBeNum(rec.data, off, 1);  // in delay slot
        int32_t id = static_cast<int32_t>(keyToLong(rec.key));
        protos[id] = std::move(bytes);
        stats_.prototypes++;
    });

    auto dis = makeDisassembler(program);

    // Instructions: key = address key; data [ProtoID][Flags]
    reader_.visitRecords(*instschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        int32_t protoId = static_cast<int32_t>(readBeNum(rec.data, off, 4));
        readBeNum(rec.data, off, 1);  // flags: source/pinned
        auto it = protos.find(protoId);
        if (it == protos.end()) {
            warn("unknown prototype id " + std::to_string(protoId));
            return;
        }
        const std::vector<uint8_t>& bytes = it->second;
        uint64_t offset = keyToImageOffset(rec.key);

        DisassembledInstruction di = dis->disassembleOne(bytes, offset);
        if (di.mnemonic.empty() || di.length <= 0) {
            stats_.disassemblyFailures++;
            return;
        }
        Address addr(space, static_cast<int64_t>(offset));        auto* inst = new Instruction(program, addr, di.mnemonic, di.length, di.flowType);
        for (size_t oi = 0; oi < di.operands.size(); ++oi) {
            inst->setOperand(static_cast<int>(oi), di.operands[oi]);
        }
        // Propagate decoded operand scalars (ownership transfers to Instruction)
        for (size_t oi = 0; oi < di.operandScalars.size(); ++oi) {
            for (auto& scalar : di.operandScalars[oi]) {
                if (scalar) {
                    inst->addOperandScalar(static_cast<int>(oi), scalar.release());
                }
            }
        }
        listing->addInstruction(inst);
        stats_.instructions++;
    });
}

// ---------------------------------------------------------------------------
// Symbols: "Symbols" -> namespaces + memory labels
// ---------------------------------------------------------------------------

void GzfProgramImporter::importSymbols(ProgramDB* program) {
    const GbfTableSchema* symschema = reader_.findTable("Symbols");
    if (!symschema) {
        warn("missing 'Symbols' table; symbols skipped");
        return;
    }
    SymbolTable* symbols = program->getSymbolTable();
    ExternalManager* externals = program->getExternalManager();
    AddressFactory* factory = program->getAddressFactory();
    AddressSpace* space =
        const_cast<AddressSpace*>(factory->getDefaultAddressSpace());
    AddressSpace* externalSpace = const_cast<AddressSpace*>(factory->getAddressSpace("EXTERNAL"));
    if (!externalSpace) {
        externalSpace = new GenericAddressSpace("EXTERNAL", 64, AddressSpace::TYPE_EXTERNAL, 0);
        if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
            paf->addAddressSpace(externalSpace);
        }
    }

    // Symbols: key = symbol id; data [Name][Address][Parent][Type][Flags]
    // Flags for the label/function source encoding; sparse columns ignored.
    struct Sym {
        int64_t id = 0;
        std::string name;
        int64_t address = 0;
        int64_t parent = 0;
        int type = 0;
        uint8_t flags = 0;
    };
    std::vector<Sym> syms;
    reader_.visitRecords(*symschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        Sym s;
        s.id = keyToLong(rec.key);
        s.name = readBeString(rec.data, off);
        s.address = readBeNum(rec.data, off, 8);
        s.parent = readBeNum(rec.data, off, 8);
        s.type = static_cast<int>(readBeNum(rec.data, off, 1));
        s.flags = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
        syms.push_back(s);
    });

    // Restore namespaces (and classes-as-namespaces) with their original ids.
    for (const Sym& s : syms) {
        if (s.type != SYMBOL_TYPE_LIBRARY && s.type != SYMBOL_TYPE_NAMESPACE &&
            s.type != SYMBOL_TYPE_CLASS) {
            continue;
        }
        Namespace* parent = symbols->getGlobalNamespace();
        const auto& nsMap = symbols->getNamespaces();
        auto pit = nsMap.find(s.parent);
        if (pit != nsMap.end() && pit->second) {
            parent = pit->second.get();
        }
        if (symbols->addNamespaceWithId(s.id, s.name, parent)) {
            stats_.namespaces++;
        }
        if (s.type == SYMBOL_TYPE_LIBRARY && externals) {
            externals->addExternalLibrary(s.name, "");
            stats_.externalLibraries++;
        }
    }

    // Labels for label-type symbols and (P3b) thunk-entry labels.
    const auto& nsMap = symbols->getNamespaces();
    for (const Sym& s : syms) {
        const uint64_t key = static_cast<uint64_t>(s.address);
        if (s.type != SYMBOL_TYPE_LABEL || s.name.empty() || s.address == 0 ||
            (key >> 32) == ADDR_KEY_EXT_SPACE) {
            continue;
        }
        Namespace* ns = symbols->getGlobalNamespace();
        auto nit = nsMap.find(s.parent);
        if (nit != nsMap.end() && nit->second) {
            ns = nit->second.get();
        }
        uint64_t offset = static_cast<uint64_t>(s.address) & 0xFFFFFFFFull;
        Address addr = imageAddress(space, offset);
        if (symbols->createLabel(addr, s.name, ns, decodeSourceType(s.flags))) {
            stats_.labels++;
        }
    }

    // External locations are regular label/function symbols whose address-map
    // key belongs to external space and whose parent is a library namespace.
    // Keep the full key for the reference phase; only its low 32 bits are the
    // external-space offset.
    auto namespacePath = [](const Namespace* ns) -> std::string {
        std::string path;
        while (ns && !ns->isGlobal()) {
            const std::string name = ns->getName();
            path = path.empty() ? name : name + "::" + path;
            ns = ns->getParent();
        }
        return path;
    };
    for (const Sym& s : syms) {
        const uint64_t key = static_cast<uint64_t>(s.address);
        if (s.name.empty() || (key >> 32) != ADDR_KEY_EXT_SPACE) {
            continue;
        }
        auto nit = nsMap.find(s.parent);
        if (nit == nsMap.end() || !nit->second) {
            warn("external symbol '" + s.name + "' has no library namespace");
            continue;
        }
        const std::string libraryName = namespacePath(nit->second.get());
        Address addr(externalSpace, static_cast<int64_t>(key & 0xFFFFFFFFull));
        const bool isFunction = s.type == SYMBOL_TYPE_FUNCTION;
        symbols->createExternalSymbol(s.id, s.name, addr, nit->second.get(),
                                      decodeSourceType(s.flags), isFunction);
        if (externals) {
            externals->addExternalLocation(libraryName, s.name, addr, s.id, "", isFunction);
        }
        externalLocationsByKey_[key] = {libraryName, s.name, addr};
        stats_.externalLocations++;
    }
}

// ---------------------------------------------------------------------------
// Functions: "Function Data" + "Thunk Functions"
// ---------------------------------------------------------------------------

void GzfProgramImporter::importFunctions(
    ProgramDB* program, const std::map<int64_t, std::string>& callingConventionsById) {
    const GbfTableSchema* fnschema = reader_.findTable("Function Data");
    if (!fnschema) {
        warn("missing 'Function Data' table; functions skipped");
        return;
    }
    FunctionManager* mgr = program->getFunctionManager();
    SymbolTable* symbols = program->getSymbolTable();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());

    // Function symbols carry the entry addresses; re-read the Symbols table
    // (key = symbol id) instead of caching state between phases.
    struct FunctionSymbol {
        std::string name;
        Namespace* ns = nullptr;
        uint8_t flags = 0;
    };
    std::map<int64_t, Address> functionEntries;   // symbol id -> entry point
    std::map<int64_t, FunctionSymbol> functionSymbols;
    if (const GbfTableSchema* symschema = reader_.findTable("Symbols")) {
        const auto& nsMap = symbols->getNamespaces();
        reader_.visitRecords(*symschema, [&](const GbfRecord& rec) {
            size_t off = 0;
            std::string name = readBeString(rec.data, off);
            int64_t address = readBeNum(rec.data, off, 8);
            int64_t parent = readBeNum(rec.data, off, 8);
            int type = static_cast<int>(readBeNum(rec.data, off, 1));
            uint8_t flags = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
            if (type != SYMBOL_TYPE_FUNCTION || address == 0) {
                return;
            }
            int64_t symId = keyToLong(rec.key);
            if (functionEntries.find(symId) != functionEntries.end()) {
                return;
            }
            uint64_t offset = static_cast<uint64_t>(address) & 0xFFFFFFFFull;
            functionEntries[symId] = imageAddress(space, offset);
            FunctionSymbol fs;
            fs.name = name;
            auto nit = nsMap.find(parent);
            fs.ns = (nit != nsMap.end() && nit->second) ? nit->second.get()
                                                        : symbols->getGlobalNamespace();
            functionSymbols[symId] = fs;
        });
    }

    // Function Data: key = function id (the function symbol's id);
    // data [Return Datatype ID][StackPurge][StackReturnOffset][StackLocalSize]
    // [Flags][Calling Convention ID][Return Storage].
    functionsById_.clear();
    reader_.visitRecords(*fnschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        int64_t returnDtId = readBeNum(rec.data, off, 8);
        readBeNum(rec.data, off, 4);  // stack purge
        readBeNum(rec.data, off, 4);  // stack return offset
        readBeNum(rec.data, off, 4);  // stack local size
        uint8_t flags = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
        uint8_t covId = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
        readBeString(rec.data, off);  // return storage string

        int64_t funcId = keyToLong(rec.key);
        auto eit = functionEntries.find(funcId);
        if (eit == functionEntries.end()) {
            warn("function id " + std::to_string(funcId) +
                 " has no matching function symbol");
            return;
        }
        auto sit = functionSymbols.find(funcId);
        if (sit == functionSymbols.end()) {
            warn("function id " + std::to_string(funcId) + " missing symbol info");
            return;
        }
        const FunctionSymbol& fs = sit->second;
        AddressSet body(eit->second, eit->second);
        Function* func = mgr->createFunction(fs.name, fs.ns, eit->second, body,
                                             decodeSourceType(fs.flags));
        if (!func) {
            func = mgr->getFunctionAt(eit->second);
            if (!func) {
                warn("failed to create function '" + fs.name + "'");
                return;
            }
        }
        // Return datatype id (FunctionDBAdapter): resolved through the
        // datatypes id map populated by the data types phase.
        if (returnDtId > 0) {
            DataType* ret = resolveDataType(returnDtId);
            if (ret) {
                func->setReturnType(ret);
                stats_.functionReturnTypes++;
            } else {
                stats_.datatypeUnresolvedRefs++;
                warn("function '" + fs.name + "' return datatype id " +
                     std::to_string(returnDtId) + " unresolved; skipped");
            }
        }
        if (flags & FUNC_INLINE_FLAG) {
            func->setInline(true);
            stats_.functionInline++;
        }
        // Calling convention id -> PrototypeModel; ids 0/1 (unknown/default)
        // are implicit, the table only defines user conventions (id >= 2).
        auto cit = callingConventionsById.find(covId);
        if (cit != callingConventionsById.end()) {
            PrototypeModel* model = mgr->getCallingConvention(cit->second);
            if (model) {
                func->setCallingConvention(model);
            }
        }
        functionsById_[funcId] = func;
        stats_.functions++;
    });

    // Thunks: key = thunk function id; data [Linked Function ID]
    if (const GbfTableSchema* thunkschema = reader_.findTable("Thunk Functions")) {
        reader_.visitRecords(*thunkschema, [&](const GbfRecord& rec) {
            int64_t thunkId = keyToLong(rec.key);
            size_t off = 0;
            int64_t linkedId = readBeNum(rec.data, off, 8);
            Function* thunk = nullptr;
            auto tit = functionsById_.find(thunkId);
            if (tit != functionsById_.end()) {
                thunk = tit->second;
            } else {
                auto eit = functionEntries.find(thunkId);
                if (eit != functionEntries.end()) {
                    thunk = mgr->getFunctionAt(eit->second);
                }
            }
            Function* linked = nullptr;
            auto lit = functionsById_.find(linkedId);
            if (lit != functionsById_.end()) {
                linked = lit->second;
            } else {
                auto eit = functionEntries.find(linkedId);
                if (eit != functionEntries.end()) {
                    linked = mgr->getFunctionAt(eit->second);
                }
            }
            if (thunk) {
                thunk->setThunk(true);
                if (linked) {
                    thunk->setThunkedFunction(linked);
                }
                stats_.thunks++;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Comments: "Comments"
// ---------------------------------------------------------------------------

void GzfProgramImporter::importComments(ProgramDB* program) {
    const GbfTableSchema* comtable = reader_.findTable("Comments");
    if (!comtable) {
        warn("missing 'Comments' table; comments skipped");
        return;
    }
    Listing* listing = program->getListing();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());

    // Comments: key = address key; data in CommentType order
    // [EOL][Pre][Post][Plate][Repeatable]
    reader_.visitRecords(*comtable, [&](const GbfRecord& rec) {
        size_t off = 0;
        std::string eol = readBeString(rec.data, off);
        std::string pre = readBeString(rec.data, off);
        std::string post = readBeString(rec.data, off);
        std::string plate = readBeString(rec.data, off);
        std::string repeatable = readBeString(rec.data, off);
        uint64_t offset = keyToImageOffset(rec.key);
        Address addr(space, static_cast<int64_t>(offset));
        CodeUnit* cu = listing->getCodeUnitAt(addr);
        if (!cu) {
            cu = listing->createData(addr, &ByteDataType::dataType(), 1);
        }
        if (!cu) {
            stats_.commentsSkippedNoAddress++;
            return;
        }
        if (!eol.empty()) cu->setComment(eol);
        if (!pre.empty()) cu->setPreComment(pre);
        if (!post.empty()) cu->setPostComment(post);
        if (!plate.empty()) cu->setPlateComment(plate);
        if (!repeatable.empty()) {
            cu->setRepeatableComment(repeatable);
            stats_.repeatableComments++;
        }
        stats_.commentsApplied++;
    });
}

// ---------------------------------------------------------------------------
// Data units: "Data" (key = address map key, data = [Data Type ID])
// ---------------------------------------------------------------------------

int GzfProgramImporter::scanTerminatedStringLength(ProgramDB* program,
                                                   const Address& addr,
                                                   int charSize) {
    Memory* memory = program->getMemory();
    if (!memory) {
        return -1;
    }
    uint8_t buf[256];
    int64_t total = 0;
    while (total < 1 << 20) {
        Address cur(addr.getAddressSpace(), addr.getOffset() + total);
        int got = memory->getBytes(cur, buf, static_cast<int>(sizeof(buf)));
        if (got <= 0) {
            break;
        }
        for (int i = 0; i + charSize <= got; i += charSize) {
            bool zero = true;
            for (int b = 0; b < charSize; ++b) {
                if (buf[i + b] != 0) {
                    zero = false;
                    break;
                }
            }
            if (zero) {
                return static_cast<int>(total + i + charSize);
            }
        }
        total += got;
    }
    return -1;
}

int GzfProgramImporter::computePEx64UnwindInfoLength(ProgramDB* program,
                                                     const Address& addr) {
    Memory* memory = program->getMemory();
    if (!memory) {
        return -1;
    }
    uint8_t hdr[4];
    if (memory->getBytes(addr, hdr, 4) != 4) {
        return -1;
    }
    uint8_t flags = static_cast<uint8_t>(hdr[0] >> 3);
    uint8_t countOfCodes = hdr[2];
    if (countOfCodes > 256) {
        return -1;  // sanity; malformed unwind info
    }
    auto align4 = [](int v) { return (v + 3) & ~3; };
    int len = 4 + 2 * countOfCodes;
    if (flags & 0x1) {
        len = align4(len) + 4;  // UNW_FLAG_EHANDLER (exception handler address)
    }
    if (flags & 0x2) {
        len = align4(len) + 4;  // UNW_FLAG_UHANDLER
    }
    if (flags & 0x4) {
        len = align4(len) + 12;  // UNW_FLAG_CHAININFO (3 dwords)
    }
    return len;
}

int GzfProgramImporter::computeRichHeaderLength(ProgramDB* program,
                                                const Address& addr) {
    Memory* memory = program->getMemory();
    if (!memory) {
        return -1;
    }
    auto readLe32 = [&](const Address& a, uint32_t& out) {
        uint8_t b[4];
        if (memory->getBytes(a, b, 4) != 4) {
            return false;
        }
        out = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
              (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
        return true;
    };
    // Mirrors Ghidra's PERichTableDataType/RichTable: a valid table starts
    // with the "DanS" signature followed by 3 xor-padded dwords and ends with
    // the "Rich" signature and the table mask; the PE signature bounds the
    // search.  The datatype layout is 4 (DanS) + 12 (padding) + 8*records +
    // 8 (signature + mask).  When no valid table is found Ghidra still lays
    // out the base 24 bytes.
    uint32_t dw = 0;
    if (!readLe32(addr, dw) || dw != 0x536E6144u) {  // "DanS"
        return 24;
    }
    int markerOffset = -1;
    uint32_t mask = 0;
    for (int i = 0; i < 100; ++i) {
        Address cur(addr.getAddressSpace(), addr.getOffset() + 4 * i);
        if (!readLe32(cur, dw)) {
            return 24;
        }
        if (dw == 0x68636952u) {  // "Rich"
            markerOffset = 4 * i;
            if (!readLe32(Address(addr.getAddressSpace(),
                                  addr.getOffset() + 4 * i + 4), mask)) {
                return 24;
            }
            break;
        }
        if (dw == 0x00004550u) {  // "PE\0\0" (IMAGE_NT_SIGNATURE)
            return 24;
        }
    }
    if (markerOffset < 0) {
        return 24;
    }
    for (int i = 1; i < 4; ++i) {  // xor-padded dwords after DanS
        Address cur(addr.getAddressSpace(), addr.getOffset() + 4 * i);
        if (!readLe32(cur, dw) || (dw ^ mask) != 0) {
            return 24;
        }
    }
    return markerOffset + 8;
}

int GzfProgramImporter::computeDataLength(ProgramDB* program, const Address& addr,
                                          DataType* dt) {
    // Dynamic placeholders report a nominal length of 1 byte; they must be
    // scanned before the generic length check so the real extent is computed.
    if (auto* ph = dynamic_cast<PlaceholderDataType*>(dt)) {
        const std::string& name = ph->getName();
        if (name == "GUID") {
            return 16;
        }
        stats_.dataPlaceholderLengths++;
        if (name == "PEx64UnwindInfoDataType") {
            stats_.dataUnwindInfo++;
            return computePEx64UnwindInfoLength(program, addr);
        }
        if (name == "PERichTableDataType") {
            stats_.dataRichHeader++;
            return computeRichHeaderLength(program, addr);
        }
        if (name == "MUIResourceDataType") {
            Memory* memory = program->getMemory();
            if (memory) {
                uint8_t hdr[132];
                if (memory->getBytes(addr, hdr, 132) == 132) {
                    static const uint8_t magic[4] = {0xCD, 0xFE, 0xCD, 0xFE};
                    if (std::memcmp(hdr, magic, 4) == 0) {
                        auto readLe32 = [](const uint8_t* p) {
                            return static_cast<uint32_t>(p[0]) |
                                   (static_cast<uint32_t>(p[1]) << 8) |
                                   (static_cast<uint32_t>(p[2]) << 16) |
                                   (static_cast<uint32_t>(p[3]) << 24);
                        };
                        // Mirrors Ghidra's MUIStructureData: the 132-byte
                        // header is followed by six size dwords (+84..+124)
                        // consumed with 8-byte alignment on the absolute
                        // address; negative (corrupt) sizes are ignored.
                        int tempOffset = 132;
                        for (int i = 0; i < 6; ++i) {
                            while (((addr.getOffset() + tempOffset) % 8) != 0) {
                                ++tempOffset;
                            }
                            uint32_t size = readLe32(hdr + 84 + i * 8 + 4);
                            if (static_cast<int32_t>(size) > 0) {
                                tempOffset += static_cast<int>(size);
                            }
                        }
                        return tempOffset;
                    }
                }
            }
            return 1;  // magic mismatch / unreadable: minimal fallback
        }
        return ph->getLength();
    }
    int length = dt->getLength();
    if (length > 0) {
        return length;
    }
    if (auto* s = dynamic_cast<StringDataType*>(dt)) {
        (void)s;
        return 1;
    }
    if (auto* u = dynamic_cast<UnicodeDataType*>(dt)) {
        (void)u;
        return 4;
    }
    if (auto* t = dynamic_cast<TerminatedStringDataType*>(dt)) {
        (void)t;
        stats_.dataTerminatedStrings++;
        return scanTerminatedStringLength(program, addr, 1);
    }
    if (dynamic_cast<TerminatedUnicodeDataType*>(dt) ||
        dynamic_cast<TerminatedUnicode32DataType*>(dt)) {
        stats_.dataTerminatedStrings++;
        return scanTerminatedStringLength(program, addr, 4);
    }
    // Unknown dynamic type: no safe length; the unit is skipped and counted.
    return -1;
}

void GzfProgramImporter::importData(ProgramDB* program) {
    const GbfTableSchema* t = reader_.findTable("Data");
    if (!t) {
        warn("missing 'Data' table; data units skipped");
        return;
    }
    Listing* listing = program->getListing();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());

    // Ghidra persists every code unit's length in "Property Map - Lengths"
    // (key = address key, value = int32).  For dynamic types (fixed strings,
    // unicode, PE rich headers, ...) this is the authoritative length — the
    // type alone cannot recompute it.  Load it first and prefer it.
    std::unordered_map<uint64_t, int32_t> pmLengths;
    if (const GbfTableSchema* pm = reader_.findTable("Property Map - Lengths")) {
        reader_.visitRecords(*pm, [&](const GbfRecord& rec) {
            uint64_t key = static_cast<uint64_t>(keyToLong(rec.key));
            int64_t len = -1;
            if (!rec.data.empty()) {
                size_t off = 0;
                len = readBeNum(rec.data, off, 4);
            } else if (!rec.sparseFields.empty()) {
                size_t off = 0;
                len = readBeNum(rec.sparseFields[0].second, off, 4);
            }
            if (len > 0) {
                pmLengths[key] = static_cast<int32_t>(len);
            }
        });
    }

    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        size_t off = 0;
        int64_t dtId = readBeNum(rec.data, off, 8);
        DataType* dt = resolveDataType(dtId);
        uint64_t offset = keyToImageOffset(rec.key);
        Address addr(space, static_cast<int64_t>(offset));
        if (!dt) {
            stats_.dataUnresolvedType++;
            warn("data at 0x" + toHexString(offset) + " has unresolved datatype id " +
                 std::to_string(dtId));
            return;
        }
        int length = -1;
        auto pmIt = pmLengths.find(static_cast<uint64_t>(keyToLong(rec.key)));
        if (pmIt != pmLengths.end()) {
            length = pmIt->second;
        }
        if (length <= 0) {
            length = computeDataLength(program, addr, dt);
        }
        if (length <= 0) {
            stats_.dataUnresolvedLength++;
            warn("data at 0x" + toHexString(offset) + " ('" + dt->getName() +
                 "') has no computable length; skipped");
            return;
        }
        Data* data = listing->createData(addr, dt, length);
        if (!data) {
            stats_.dataConflicts++;
            warn("data at 0x" + toHexString(offset) + " ('" + dt->getName() +
                 "') conflicts with an existing code unit; skipped");
            return;
        }
        stats_.dataUnits++;
    });
}

// ---------------------------------------------------------------------------
// Equates: "Equates" + "Equate References" tables
// ---------------------------------------------------------------------------

void GzfProgramImporter::importEquates(ProgramDB* program) {
    // Equates (EquateDBAdapterV0): key = long auto-increment equate id;
    // data = [String "Equate Name"][Long "Equate Value"].
    const GbfTableSchema* t = reader_.findTable("Equates");
    if (!t || t->recordCount == 0) {
        return;
    }
    EquateTable* equateTable = program->getEquateTable();
    if (!equateTable) {
        warn("no equate table in the program; " + std::to_string(t->recordCount) +
             " equates skipped");
        stats_.equatesBad += static_cast<int>(t->recordCount);
        return;
    }
    std::map<int64_t, Equate*> equatesById;
    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        size_t off = 0;
        std::string name = readBeString(rec.data, off);
        int64_t value = readBeNum(rec.data, off, 8);
        if (name.empty()) {
            stats_.equatesBad++;
            warn("equate with an empty name; skipped");
            return;
        }
        Equate* eq = equateTable->getEquate(name);
        if (!eq) {
            eq = equateTable->createEquate(name, value);
        }
        if (!eq) {
            stats_.equatesBad++;
            return;
        }
        equatesById[keyToLong(rec.key)] = eq;
        stats_.equates++;
    });

    // Equate references (EquateRefDBAdapterV1): key = long auto-increment
    // reference id; data = [Long "Equate ID"][Long "Equate Reference"]
    // [Short "Operand Index"][Long "Varnode Hash"].  The varnode hash binds
    // a dynamic (stack/computed) varnode; the engine tracks address+operand
    // only, so the hash is validated and otherwise not retained.
    const GbfTableSchema* rt = reader_.findTable("Equate References");
    if (!rt || rt->recordCount == 0) {
        return;
    }
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!space) {
        warn("no default address space; " + std::to_string(rt->recordCount) +
             " equate references skipped");
        stats_.equatesBad += static_cast<int>(rt->recordCount);
        return;
    }
    reader_.visitRecords(*rt, [&](const GbfRecord& rec) {
        size_t off = 0;
        int64_t equateId = readBeNum(rec.data, off, 8);
        int64_t addrKey = readBeNum(rec.data, off, 8);
        int64_t opIndex = readBeNum(rec.data, off, 2);
        readBeNum(rec.data, off, 8);  // varnode hash
        auto it = equatesById.find(equateId);
        if (it == equatesById.end()) {
            stats_.equatesBad++;
            warn("equate reference with unknown equate id; skipped");
            return;
        }
        if ((static_cast<uint64_t>(addrKey) >> 32) != ADDR_KEY_IMAGE_SPACE) {
            stats_.equatesBad++;
            warn("equate reference outside the image space; skipped");
            return;
        }
        Address addr = imageAddress(space, static_cast<uint64_t>(addrKey) & 0xFFFFFFFFull);
        if (!equateTable->addReference(it->second, addr, static_cast<int>(opIndex))) {
            stats_.equatesBad++;
            return;
        }
        stats_.equateReferences++;
    });
}

// ---------------------------------------------------------------------------
// References: "FROM REFS" (RefListV0 record encoding)
// ---------------------------------------------------------------------------

void GzfProgramImporter::importReferences(ProgramDB* program) {
    const GbfTableSchema* refschema = reader_.findTable("FROM REFS");
    if (!refschema) {
        warn("missing 'FROM REFS' table; references skipped");
        return;
    }
    ReferenceManager* mgr = program->getReferenceManager();
    AddressFactory* factory = program->getAddressFactory();
    AddressSpace* space =
        const_cast<AddressSpace*>(factory->getDefaultAddressSpace());
    if (!mgr || !space) {
        warn("no reference manager / address factory; references skipped");
        return;
    }

    // Register-space refs carry database-specific space indexes; a register
    // space is created lazily and Register objects cached by register address.
    AddressSpace* regSpace = nullptr;
    std::map<int64_t, std::unique_ptr<Register>> registerCache;
    const int registerBytes =
        program->getLanguageID().getIdAsString().find("64") != std::string::npos ? 8 : 4;

    // Record layout (RefListV0): key = from-address map key; data
    // [int numRefs][binary ref data]; per ref:
    //   [8B BE addrKey][1B flags][1B refType][1B opIndex]
    //   [+8B symbolId if flags & 0x08][+8B offsetOrShift if flags & 0x14].
    reader_.visitRecords(*refschema, [&](const GbfRecord& rec) {
        if (rec.data.size() < 4) {
            stats_.refsBadRecords++;
            return;
        }
        size_t off = 0;
        int64_t numRefs = readBeNum(rec.data, off, 4);
        std::vector<uint8_t> bin = readBeBinary(rec.data, off);
        int64_t fromKey = keyToLong(rec.key);

        size_t pos = 0;
        int64_t decoded = 0;
        while (pos < bin.size()) {
            if (pos + 11 > bin.size()) {
                stats_.refsBadRecords++;
                break;
            }
            uint64_t toKey = static_cast<uint64_t>(readBeNum(bin, pos, 8));
            uint8_t flags = static_cast<uint8_t>(bin[pos++]);
            int8_t typeVal = static_cast<int8_t>(bin[pos++]);
            int8_t opIndex = static_cast<int8_t>(bin[pos++]);
            int64_t symbolId = -1;
            if (flags & REF_FLAG_HAS_SYMBOL_ID) {
                if (pos + 8 > bin.size()) {
                    stats_.refsBadRecords++;
                    break;
                }
                symbolId = readBeNum(bin, pos, 8);
            }
            uint64_t offsetOrShift = 0;
            if (flags & (REF_FLAG_OFFSET | REF_FLAG_SHIFT)) {
                if (pos + 8 > bin.size()) {
                    stats_.refsBadRecords++;
                    break;
                }
                offsetOrShift = static_cast<uint64_t>(readBeNum(bin, pos, 8));
            }
            decoded++;

            const RefType* type = refTypeByValue(typeVal);
            if (!type) {
                warn("reference with unknown ref type " + std::to_string(typeVal));
                continue;
            }
            const uint64_t fromHi =
                static_cast<uint64_t>(fromKey) >> 32;
            const uint64_t toHi = (toKey & 0xFFFFFFFF00000000ull) >> 32;
            if (fromHi == ADDR_KEY_EXT_SPACE || fromKey == -1 || fromKey == -2) {
                // Entry-point references: from is the (single) external entry
                // record; there is no from address in program memory.
                stats_.refsEntryPoint++;
                continue;
            }
            if (toHi == ADDR_KEY_STACK_SPACE) {
                // Stack references: "to" key is the stack-space address whose
                // low 32 bits are the signed stack offset (sp + offset).
                int32_t stackOffset = static_cast<int32_t>(toKey & 0xFFFFFFFFull);
                Address from = imageAddress(space, static_cast<uint64_t>(fromKey) & 0xFFFFFFFFull);
                Reference* ref = mgr->addStackReference(from, opIndex, stackOffset, type,
                                                        decodeRefSource(flags));
                if (!ref) {
                    stats_.refsBadRecords++;
                    continue;
                }
                if (!(flags & REF_FLAG_PRIMARY)) {
                    mgr->setPrimary(ref, false);
                }
                stats_.references++;
                continue;
            }
            if (toHi == ADDR_KEY_EXT_SPACE) {
                auto ext = externalLocationsByKey_.find(toKey);
                if (ext == externalLocationsByKey_.end()) {
                    stats_.refsExternTarget++;
                    warn("reference targets unknown external address 0x" +
                         std::to_string(toKey & 0xFFFFFFFFull));
                    continue;
                }
                Address from = imageAddress(space, static_cast<uint64_t>(fromKey) & 0xFFFFFFFFull);
                Reference* ref = mgr->addExternalReference(
                    from, ext->second.libraryName, ext->second.label, ext->second.address,
                    decodeRefSource(flags), opIndex, type);
                if (!ref) {
                    stats_.refsBadRecords++;
                    continue;
                }
                if (!(flags & REF_FLAG_PRIMARY)) {
                    mgr->setPrimary(ref, false);
                }
                if (symbolId >= 0) {
                    stats_.refsWithSymbolId++;
                }
                stats_.references++;
                stats_.externalReferences++;
                continue;
            }
            if (toHi != ADDR_KEY_IMAGE_SPACE && (toKey >> 60) == 0x2) {
                // Register-space reference.  The register space carries a
                // database-specific space index (low 28 bits of the top half;
                // e.g. 0x20000001/0x20000002/0x20000003 across the corpora),
                // so only the top nibble (shared with the image space) is
                // reliable.  The low 32 bits are the register address.
                if (!regSpace) {
                    AddressSpace* factoryReg = const_cast<AddressSpace*>(
                        factory->getRegisterSpace());
                    if (factoryReg) {
                        regSpace = factoryReg;
                    } else {
                        regSpace = new GenericAddressSpace("register", 64,
                                                           AddressSpace::TYPE_REGISTER, 0);
                        if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
                            paf->addAddressSpace(regSpace);
                            paf->setRegisterSpace(regSpace);
                        }
                    }
                }
                int64_t regOffset = static_cast<int64_t>(toKey & 0xFFFFFFFFull);
                std::unique_ptr<Register>& reg = registerCache[regOffset];
                if (!reg) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "r_0x%llx",
                                  static_cast<unsigned long long>(regOffset));
                    reg = std::make_unique<Register>(buf, "", Address(regSpace, regOffset),
                                                     registerBytes, /*bigEndian=*/false, 0);
                }
                Address from = imageAddress(space, static_cast<uint64_t>(fromKey) & 0xFFFFFFFFull);
                Reference* ref =
                    mgr->addRegisterReference(from, opIndex, reg.get(), type,
                                              decodeRefSource(flags));
                if (!ref) {
                    stats_.refsBadRecords++;
                    continue;
                }
                if (!(flags & REF_FLAG_PRIMARY)) {
                    mgr->setPrimary(ref, false);
                }
                stats_.references++;
                continue;
            }
            if (fromHi != ADDR_KEY_IMAGE_SPACE || toHi != ADDR_KEY_IMAGE_SPACE) {
                stats_.refsUnknownSpace++;
                continue;
            }

            Address from = imageAddress(space, static_cast<uint64_t>(fromKey) & 0xFFFFFFFFull);
            Address to = imageAddress(space, static_cast<uint64_t>(toKey) & 0xFFFFFFFFull);
            Reference* ref = nullptr;
            if (flags & REF_FLAG_SHIFT) {
                ref = mgr->addShiftedMemReference(from, to, static_cast<int>(offsetOrShift),
                                                  type, decodeRefSource(flags), opIndex);
            } else if (flags & REF_FLAG_OFFSET) {
                ref = mgr->addOffsetMemReference(from, to, /*toAddrIsBase=*/true,
                                                 static_cast<long>(offsetOrShift), type,
                                                 decodeRefSource(flags), opIndex);
            } else {
                ref = mgr->addMemoryReference(from, to, type, decodeRefSource(flags), opIndex);
            }
            if (!ref) {
                stats_.refsBadRecords++;
                continue;
            }
            if (!(flags & REF_FLAG_PRIMARY)) {
                mgr->setPrimary(ref, false);
            }
            if (symbolId >= 0) {
                stats_.refsWithSymbolId++;
            }
            if (flags & (REF_FLAG_OFFSET | REF_FLAG_SHIFT)) {
                stats_.refsWithOffsetOrShift++;
            }
            stats_.references++;
        }
        if (decoded != numRefs) {
            stats_.refsBadRecords++;
        }
    });
}

// ---------------------------------------------------------------------------
// Context table: "ContextTable" (PrototypeManager CONTEXT_TABLE_NAME)
// ---------------------------------------------------------------------------
// Ghidra stores, per instruction prototype, the disassembly-context value of
// the language's base context register (PrototypeManager.getID serializes
// getRegisterValue(baseContextRegister) as the unsigned value).  The engine
// decodes x86 with its own disassembler and does not re-create prototypes
// from contexts, so the table is validated (prototype id range, decimal
// parse) and counted rather than applied to the program context.
void GzfProgramImporter::importContextTable(ProgramDB* program) {
    const GbfTableSchema* t = reader_.findTable("ContextTable");
    if (!t) {
        return;
    }
    // Every record carries the same base-context register value for the
    // language.  Enigma's semantic equivalent is a DEFAULT register-context
    // value spanning the image (ProgramContext defaults), so the first valid
    // value is applied once; the remaining records are still validated.
    ProgramContext* context = program->getProgramContext();
    auto* ctxImpl = dynamic_cast<ProgramContextImpl*>(context);
    bool haveValue = false;
    uint64_t contextValue = 0;
    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        size_t off = 0;
        const std::string value = readBeString(rec.data, off);
        const int64_t protoId = keyToLong(rec.key);
        char* end = nullptr;
        errno = 0;
        const uint64_t parsed = std::strtoull(value.c_str(), &end, 10);
        if (end == value.c_str() || *end != '\0' || errno == ERANGE || protoId < 0 ||
            protoId >= stats_.prototypes) {
            stats_.contextRecordsBad++;
            warn("ContextTable record with invalid prototype id or context value (key=" +
                 std::to_string(protoId) + ")");
            return;
        }
        if (!haveValue) {
            haveValue = true;
            contextValue = parsed;
        }
        stats_.contextRecords++;
    });
    if (!ctxImpl || !haveValue) {
        return;
    }
    // The program min/max addresses are not established at import time; the
    // memory map's extent is the range the default context spans.
    Memory* memory = program->getMemory();
    Address rangeMin;
    Address rangeMax;
    if (memory) {
        for (MemoryBlock* block : memory->getBlocks()) {
            if (!block) continue;
            if (!rangeMin.isValid() || block->getStart() < rangeMin) {
                rangeMin = block->getStart();
            }
            if (!rangeMax.isValid() || block->getEnd() > rangeMax) {
                rangeMax = block->getEnd();
            }
        }
    }
    if (!rangeMin.isValid() || !rangeMax.isValid()) {
        return;
    }
    // Context register: reuse the language's, or synthesize an 8-byte one at
    // register-space offset 0 (the base context register is 8 bytes in both
    // x86-64 and x86-32 languages of the corpora).
    Register* reg = context->getContextRegister();
    if (!reg) {
        AddressFactory* factory = program->getAddressFactory();
        AddressSpace* regSpace = const_cast<AddressSpace*>(factory->getRegisterSpace());
        if (!regSpace) {
            regSpace = new GenericAddressSpace("register", 64,
                                               AddressSpace::TYPE_REGISTER, 0);
            if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
                paf->addAddressSpace(regSpace);
                paf->setRegisterSpace(regSpace);
            }
        }
        reg = ctxImpl->addOwnedRegister(std::make_unique<Register>(
            "context", "", Address(regSpace, 0), 8, /*bigEndian=*/false, 0));
        if (auto* nc = const_cast<ProgramContext*>(context)) {
            nc->setContextRegister(reg);
        }
    }
    const int regSize = reg->getNumBytes() > 0 ? reg->getNumBytes() : 8;
    RegisterValue rv(reg, contextValue, regSize);
    ctxImpl->setDefaultValue(&rv, rangeMin, rangeMax);
    stats_.contextDefaults++;
}

// ---------------------------------------------------------------------------
// Register value maps: "Range Map - Register_<name>" tables
// ---------------------------------------------------------------------------
// Ghidra's AbstractStoredProgramContext keeps current register values in
// DatabaseRangeMapAdapter tables named "Range Map - Register_" + register
// name.  Each record: key = start (address-map key), field To = end
// (address-map key, inclusive), field Value = BinaryField holding
// RegisterValue.toBytes(): [mask][value] halves, each n bytes MSB-first
// where n = base-mask length = register size.
void GzfProgramImporter::importRegisterValueMaps(ProgramDB* program) {
    ProgramContext* context = program->getProgramContext();
    AddressFactory* factory = program->getAddressFactory();
    AddressSpace* space = const_cast<AddressSpace*>(factory->getDefaultAddressSpace());
    if (!context || !space) {
        return;
    }
    const std::string prefix = "Range Map - Register_";
    const int registerBytes =
        program->getLanguageID().getIdAsString().find("64") != std::string::npos ? 8 : 4;
    // Register-space offsets of language registers the engine knows
    // (ia.sinc: "define register offset=0x110 [ FS_OFFSET GS_OFFSET ]").
    const std::map<std::string, int64_t> knownOffsets = {
        {"FS_OFFSET", 0x110},
        {"GS_OFFSET", 0x110},
    };

    for (const GbfTableSchema& t : reader_.tables()) {
        if (t.name.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        const std::string regName = t.name.substr(prefix.size());
        const int64_t regOffset = [&]() {
            auto known = knownOffsets.find(regName);
            if (known != knownOffsets.end()) {
                return known->second;
            }
            warn("register value map for unknown register '" + regName +
                 "'; using synthetic register-space offset 0");
            return static_cast<int64_t>(0);
        }();
        AddressSpace* regSpace = const_cast<AddressSpace*>(factory->getRegisterSpace());
        if (!regSpace) {
            regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 0);
            if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
                paf->addAddressSpace(regSpace);
                paf->setRegisterSpace(regSpace);
            }
        }
        auto* ctxImpl = dynamic_cast<ProgramContextImpl*>(context);
        Register* reg =
            ctxImpl ? ctxImpl->addOwnedRegister(std::make_unique<Register>(
                          regName, "", Address(regSpace, regOffset), registerBytes,
                          /*bigEndian=*/false, 0))
                    : nullptr;
        if (!reg) {
            stats_.registerValueBad += static_cast<int>(t.recordCount);
            warn("no program context to hold register value map '" + t.name + "'");
            continue;
        }
        reader_.visitRecords(t, [&](const GbfRecord& rec) {
            size_t off = 0;
            const int64_t toKey = readBeNum(rec.data, off, 8);
            std::vector<uint8_t> blob = readBeBinary(rec.data, off);
            const int64_t fromKey = keyToLong(rec.key);
            if (blob.size() != 2 * static_cast<size_t>(registerBytes) ||
                (static_cast<uint64_t>(fromKey) >> 32) != ADDR_KEY_IMAGE_SPACE ||
                (static_cast<uint64_t>(toKey) >> 32) != ADDR_KEY_IMAGE_SPACE) {
                stats_.registerValueBad++;
                warn("register value map record with unexpected key or value size");
                return;
            }
            Address start = imageAddress(space, static_cast<uint64_t>(fromKey) & 0xFFFFFFFFull);
            Address end = imageAddress(space, static_cast<uint64_t>(toKey) & 0xFFFFFFFFull);
            // RegisterValue.toBytes(): [mask][value] halves, each MSB-first;
            // the engine stores register bytes LSB-first.
            std::vector<uint8_t> mask(blob.begin(), blob.begin() + registerBytes);
            std::vector<uint8_t> value(blob.begin() + registerBytes, blob.end());
            std::reverse(mask.begin(), mask.end());
            std::reverse(value.begin(), value.end());
            RegisterValue rv(reg, value, mask);
            context->setRegisterValue(&rv, start, end);
            stats_.registerValueRanges++;
        });
    }
}

// ---------------------------------------------------------------------------
// Bookmarks: "Bookmark Types" + per-type "Bookmarks{typeId}" tables
// ---------------------------------------------------------------------------
// Ghidra's BookmarkDBManager keeps one table per bookmark type named
// "Bookmarks" + type id (BookmarkDBAdapterV3): fields [Address][Category]
// [Comment].  The engine keys bookmarks by (address, type) and has no
// category/type registry, so the Ghidra category string is folded into the
// engine's type slot (every corpus category is unique per address in the
// PE corpora); the "Bookmark Types" names are validated and counted only.
void GzfProgramImporter::importBookmarks(ProgramDB* program) {
    BookmarkManager* bm = program->getBookmarkManager();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!bm || !space) {
        warn("no bookmark manager; bookmarks skipped");
        return;
    }
    std::map<int64_t, std::string> typeNames;
    if (const GbfTableSchema* t = reader_.findTable("Bookmark Types")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            int64_t id = keyToLong(rec.key);
            size_t off = 0;
            typeNames[id] = readBeString(rec.data, off);
            stats_.bookmarkTypes++;
        });
    }
    const std::string prefix = "Bookmarks";
    for (const GbfTableSchema& t : reader_.tables()) {
        if (t.name.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        if (t.isIndexTable()) {
            continue;
        }
        const std::string suffix = t.name.substr(prefix.size());
        if (suffix.empty() || suffix.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }
        int64_t typeId = -1;
        try {
            typeId = std::stoll(suffix);
        } catch (const std::exception&) {
            typeId = -1;
        }
        if (typeNames.find(typeId) == typeNames.end()) {
            stats_.bookmarksBad += static_cast<int>(t.recordCount);
            warn("bookmark table '" + t.name + "' has no matching bookmark type");
            continue;
        }
        reader_.visitRecords(t, [&](const GbfRecord& rec) {
            size_t off = 0;
            const int64_t addrKey = readBeNum(rec.data, off, 8);
            std::string category = readBeString(rec.data, off);
            std::string comment = readBeString(rec.data, off);
            if ((static_cast<uint64_t>(addrKey) >> 32) != ADDR_KEY_IMAGE_SPACE) {
                stats_.bookmarksBad++;
                warn("bookmark outside the image space (key 0x" +
                 toHexString(static_cast<uint64_t>(keyToLong(rec.key))) + "); skipped");
                return;
            }
            Address addr = imageAddress(space, static_cast<uint64_t>(addrKey) & 0xFFFFFFFFull);
            if (!bm->setBookmark(addr, category, comment)) {
                stats_.bookmarksBad++;
                return;
            }
            stats_.bookmarks++;
        });
    }
}

// ---------------------------------------------------------------------------
// Relocations: "Relocations" (RelocationDBAdapterV6)
// ---------------------------------------------------------------------------
// Fields [Address][Status byte][Type int][Values BinaryCodedField][Bytes]
// [Symbol Name].  Status ordinals match Relocation.Status.  Values is a
// BinaryCodedField: byte 0 = array type (0=byte, 3=short, 4=int, 5=long
// array; 1/2 = float/double), byte 1 = 0xFF for null or 0x00 followed by
// big-endian elements.  Floats/doubles are preserved as bit patterns in the
// engine's int64 value slot.
void GzfProgramImporter::importRelocations(ProgramDB* program) {
    const GbfTableSchema* t = reader_.findTable("Relocations");
    if (!t) {
        return;
    }
    auto* impl = dynamic_cast<RelocationTableImpl*>(program->getRelocationTable());
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!impl || !space) {
        warn("no relocation table; relocations skipped");
        return;
    }
    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        size_t off = 0;
        const int64_t addrKey = readBeNum(rec.data, off, 8);
        const int64_t statusVal = readBeNum(rec.data, off, 1);
        const int64_t typeVal = readBeNum(rec.data, off, 4);
        std::vector<uint8_t> values = readBeBinary(rec.data, off);
        std::vector<uint8_t> bytes = readBeBinary(rec.data, off);
        std::string symbolName = readBeString(rec.data, off);
        if ((static_cast<uint64_t>(addrKey) >> 32) != ADDR_KEY_IMAGE_SPACE) {
            stats_.relocationsBad++;
            warn("relocation outside the image space; skipped");
            return;
        }
        Relocation::Status status = Relocation::Status::UNKNOWN;
        try {
            status = Relocation::getStatus(static_cast<int>(statusVal));
        } catch (const std::invalid_argument&) {
            // Newer Ghidra writes relocation-bookkeeping statuses beyond the
            // engine's model (e.g. C++ RTTI/vtable entries carry 70).  The
            // analytical content - address, type, values, symbol name - is
            // fully preserved; only the bookkeeping status is clamped.
            status = Relocation::Status::APPLIED_OTHER;
            stats_.relocationsStatusClamped++;
        }
        std::vector<int64_t> decodedValues;
        if (!values.empty()) {
            const uint8_t bcfType = values[0];
            const bool isNull = values.size() < 2 || values[1] == 0xFF;
            size_t pos = isNull ? values.size() : 2;
            if (bcfType == BCF_BYTE_ARRAY) {
                for (; pos < values.size(); ++pos) {
                    decodedValues.push_back(values[pos]);
                }
            } else if (bcfType == BCF_SHORT_ARRAY || bcfType == BCF_INT_ARRAY ||
                       bcfType == BCF_LONG_ARRAY) {
                const size_t elemSize = bcfType == BCF_SHORT_ARRAY ? 2
                                        : bcfType == BCF_INT_ARRAY  ? 4
                                                                    : 8;
                for (; pos + elemSize <= values.size(); pos += elemSize) {
                    decodedValues.push_back(readBeNum(values, pos, elemSize));
                }
            } else if (bcfType == 1 && pos + 4 <= values.size()) {  // float
                decodedValues.push_back(readBeNum(values, pos, 4));
            } else if (bcfType == 2 && pos + 8 <= values.size()) {  // double
                decodedValues.push_back(readBeNum(values, pos, 8));
            } else if (!isNull) {
                stats_.relocationsBad++;
                warn("relocation with unknown BinaryCodedField type " +
                     std::to_string(bcfType));
            }
        }
        Address addr = imageAddress(space, static_cast<uint64_t>(addrKey) & 0xFFFFFFFFull);
        impl->addRelocation(addr, status, static_cast<int>(typeVal), decodedValues,
                            bytes, symbolName);
        stats_.relocations++;
    });
}

// ---------------------------------------------------------------------------
// Module tree: "Trees" + per-tree module/fragment/relationship tables
// ---------------------------------------------------------------------------
// TreeManagerDB layout: "Trees" (key = tree id, [Name][Modification Number]);
// per tree "Module Table{N}" / "Fragment Table{N}" /
// "Parent/Child Relationships{N}" / "Range Map - Fragment Addresses{N}".
// Fragment child ids are stored NEGATED in the relationship table
// (ModuleDB negates fragment ids when persisting children), so fragments are
// loaded under -dbKey; module ids are stored as-is.
void GzfProgramImporter::importModuleTree(ProgramDB* program) {
    TreeManager* treeMgr = program->getTreeManager();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!treeMgr || !space) {
        warn("no tree manager; module tree skipped");
        return;
    }
    struct TreeRow {
        int64_t id;
        std::string name;
        int64_t modNumber;
    };
    std::vector<TreeRow> treeRows;
    if (const GbfTableSchema* t = reader_.findTable("Trees")) {
        reader_.visitRecords(*t, [&](const GbfRecord& rec) {
            size_t off = 0;
            TreeRow row;
            row.id = keyToLong(rec.key);
            row.name = readBeString(rec.data, off);
            row.modNumber = readBeNum(rec.data, off, 8);
            treeRows.push_back(row);
        });
    }
    // ADDRESS MAP: key = base index; data [Space Name][Segment][Deleted].
    // Relocatable address keys (type 0x2) address base 0 in the image space;
    // other bases of the default space (e.g. the "tdb" block Ghidra maps at
    // ram:0xff00000000) encode offsets relative to base = segment << 32.
    std::map<int64_t, int64_t> baseSegments;
    if (const GbfTableSchema* at = reader_.findTable("ADDRESS MAP")) {
        const std::string defaultName = space->getName();
        reader_.visitRecords(*at, [&](const GbfRecord& rec) {
            size_t off = 0;
            const std::string name = readBeString(rec.data, off);
            const int64_t segment = readBeNum(rec.data, off, 4);
            if (name == defaultName) {
                baseSegments[keyToLong(rec.key)] = segment;
            }
        });
    }
    // Decode a relocatable address key into an image-relative engine offset,
    // or -1 if it cannot be decoded (non-relocatable type or unknown base).
    auto decodeKey = [&](int64_t key) -> int64_t {
        const uint64_t ukey = static_cast<uint64_t>(key);
        if ((ukey >> 60) != 0x2) {  // RELOCATABLE_ADDR_TYPE
            return -1;
        }
        const int64_t low = static_cast<int64_t>(ukey & 0xFFFFFFFFull);
        const int64_t baseIndex = static_cast<int64_t>((ukey >> 32) & 0x1FFFFFFF);
        if (baseIndex == 0) {
            // Image space (base 0): offset is an RVA relative to the image
            // base; other bases are absolute (segment << 32) mappings.
            return static_cast<int64_t>(static_cast<uint64_t>(imageBase_) +
                                        static_cast<uint64_t>(low));
        }
        const auto bit = baseSegments.find(baseIndex);
        if (bit == baseSegments.end()) {
            return -1;
        }
        const int64_t offset = (bit->second << 32) + low;
        return offset < 0 ? -1 : offset;
    };
    for (const TreeRow& row : treeRows) {
        // The engine pre-creates the default tree; extra trees are created by
        // name.  Tree ids are internal db keys nothing else references, so the
        // engine's own id sequence is used for additional trees.
        ModuleManager* mm = nullptr;
        for (const auto& pair : treeMgr->getModules()) {
            if (pair.first == row.name) {
                mm = pair.second.get();
                break;
            }
        }
        if (!mm) {
            if (!treeMgr->createRootModule(row.name)) {
                stats_.moduleTreeBad++;
                warn("failed to create tree '" + row.name + "'");
                continue;
            }
            for (const auto& pair : treeMgr->getModules()) {
                if (pair.first == row.name) {
                    mm = pair.second.get();
                    break;
                }
            }
        }
        if (!mm) {
            stats_.moduleTreeBad++;
            warn("tree '" + row.name + "' is missing its module manager");
            continue;
        }
        mm->setModificationNumber(row.modNumber);
        stats_.trees++;

        const std::string suffix = std::to_string(row.id);
        // Module Table{N}: key = module id (0 = root); data [Name][Comments]
        // [Child Count].
        if (const GbfTableSchema* t = reader_.findTable("Module Table" + suffix)) {
            reader_.visitRecords(*t, [&](const GbfRecord& rec) {
                size_t off = 0;
                std::string name = readBeString(rec.data, off);
                std::string comment = readBeString(rec.data, off);
                readBeNum(rec.data, off, 4);  // child count (derived)
                int64_t id = keyToLong(rec.key);
                if (!mm->loadModule(id, name, comment)) {
                    stats_.moduleTreeBad++;
                    return;
                }
                stats_.modules++;
            });
        }
        // Fragment Table{N}: key = fragment id; data [Name][Comments].  Loaded
        // under -id so relationships (stored negated) resolve to fragments.
        if (const GbfTableSchema* t = reader_.findTable("Fragment Table" + suffix)) {
            reader_.visitRecords(*t, [&](const GbfRecord& rec) {
                size_t off = 0;
                std::string name = readBeString(rec.data, off);
                std::string comment = readBeString(rec.data, off);
                int64_t id = keyToLong(rec.key);
                if (!mm->loadFragment(-id, name, comment)) {
                    stats_.moduleTreeBad++;
                    return;
                }
                stats_.fragments++;
            });
        }
        // Parent/Child Relationships{N}: key = ordinal; data [Parent ID]
        // [Child ID][Child Index].  Processed in key order so the sibling
        // ordering is preserved.
        if (const GbfTableSchema* t =
                reader_.findTable("Parent/Child Relationships" + suffix)) {
            reader_.visitRecords(*t, [&](const GbfRecord& rec) {
                size_t off = 0;
                int64_t parent = readBeNum(rec.data, off, 8);
                int64_t child = readBeNum(rec.data, off, 8);
                int childIndex = static_cast<int>(readBeNum(rec.data, off, 4));
                mm->addRelationship(parent, child, childIndex);
                stats_.moduleRelationships++;
            });
        }
        // Range Map - Fragment Addresses{N}: key = start (address-map key);
        // data [End (inclusive)][Fragment DB key].
        if (const GbfTableSchema* t =
                reader_.findTable("Range Map - Fragment Addresses" + suffix)) {
            const auto& frags = mm->getFragments();
            reader_.visitRecords(*t, [&](const GbfRecord& rec) {
                size_t off = 0;
                const int64_t toKey = readBeNum(rec.data, off, 8);
                const int64_t fragKey = readBeNum(rec.data, off, 8);
                const int64_t fromKey = keyToLong(rec.key);
                const int64_t fromOffset = decodeKey(fromKey);
                const int64_t toOffset = decodeKey(toKey);
                if (fromOffset < 0 || toOffset < 0) {
                    stats_.moduleTreeBad++;
                    warn("fragment address range outside the image space (from key 0x" +
                 toHexString(static_cast<uint64_t>(fromKey)) + ")");
                    return;
                }
                auto fit = frags.find(-fragKey);
                if (fit == frags.end()) {
                    stats_.moduleTreeBad++;
                    warn("fragment address range references unknown fragment " +
                         std::to_string(fragKey));
                    return;
                }
                fit->second->addRange(Address(space, fromOffset), Address(space, toOffset));
                stats_.fragmentRanges++;
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Function scopes: "Range Map - SCOPE ADDRESSES"
// ---------------------------------------------------------------------------
// Ghidra's NamespaceManager stores every function's body in this range map
// (key = start address-map key, [End (inclusive)][Function id]); it is the
// authoritative function-body storage, so the single-address bodies created
// by the functions phase are replaced with the accumulated corpus ranges.
void GzfProgramImporter::importFunctionScopes(ProgramDB* program) {
    const GbfTableSchema* t = reader_.findTable("Range Map - SCOPE ADDRESSES");
    if (!t) {
        return;
    }
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!space) {
        return;
    }
    std::map<int64_t, AddressSet> bodiesById;
    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        size_t off = 0;
        const int64_t toKey = readBeNum(rec.data, off, 8);
        const int64_t funcId = readBeNum(rec.data, off, 8);
        const int64_t fromKey = keyToLong(rec.key);
        if ((static_cast<uint64_t>(fromKey) >> 32) != ADDR_KEY_IMAGE_SPACE ||
            (static_cast<uint64_t>(toKey) >> 32) != ADDR_KEY_IMAGE_SPACE) {
            stats_.scopeBad++;
            warn("function scope range outside the image space");
            return;
        }
        bodiesById[funcId].add(imageAddress(space, static_cast<uint64_t>(fromKey) & 0xFFFFFFFFull),
                               imageAddress(space, static_cast<uint64_t>(toKey) & 0xFFFFFFFFull));
        stats_.scopeRanges++;
    });
    for (const auto& entry : bodiesById) {
        auto fit = functionsById_.find(entry.first);
        if (fit == functionsById_.end()) {
            stats_.scopeBad++;
            warn("function scope references unknown function id " +
                 std::to_string(entry.first));
            continue;
        }
        fit->second->setBody(entry.second);
        stats_.functionsWithScopes++;
    }
}

// ---------------------------------------------------------------------------
// Function tags: "Function Tags" (key = long tag id; data [String tag][String
// comment]) and "Function Tag Map" (key = long map id; data [Long function
// id][Long tag id]).  The function id is the function symbol's id, the same
// value that keys the "Function Data" records and functionsById_.
// ---------------------------------------------------------------------------

void GzfProgramImporter::importFunctionTags(ProgramDB* program) {
    const GbfTableSchema* tags = reader_.findTable("Function Tags");
    if (!tags) {
        return;
    }
    FunctionTagManager* ftm = program->getFunctionTagManager();
    if (!ftm) {
        return;
    }
    std::map<int64_t, FunctionTag*> tagsById;
    reader_.visitRecords(*tags, [&](const GbfRecord& rec) {
        size_t off = 0;
        const std::string name = readBeString(rec.data, off);
        const std::string comment = readBeString(rec.data, off);
        if (name.empty()) {
            stats_.functionTagsBad++;
            warn("function tag record with empty name");
            return;
        }
        FunctionTag* tag = ftm->getFunctionTag(name);
        if (!tag) {
            tag = ftm->createFunctionTag(name, comment);
        }
        tagsById[keyToLong(rec.key)] = tag;
        stats_.functionTags++;
    });
    const GbfTableSchema* map = reader_.findTable("Function Tag Map");
    if (!map || tagsById.empty()) {
        return;
    }
    reader_.visitRecords(*map, [&](const GbfRecord& rec) {
        size_t off = 0;
        const int64_t funcId = readBeNum(rec.data, off, 8);
        const int64_t tagId = readBeNum(rec.data, off, 8);
        auto tit = tagsById.find(tagId);
        if (tit == tagsById.end()) {
            stats_.functionTagAssignmentsBad++;
            warn("function tag assignment references unknown tag id " +
                 std::to_string(tagId));
            return;
        }
        auto fit = functionsById_.find(funcId);
        if (fit == functionsById_.end()) {
            stats_.functionTagAssignmentsBad++;
            warn("function tag assignment references unknown function id " +
                 std::to_string(funcId));
            return;
        }
        fit->second->addTagDirect(tit->second);
        stats_.functionTagAssignments++;
    });
}

// ---------------------------------------------------------------------------
// Entry points: FROM REFS records keyed -1/-2 (the external-entry pseudo
// address).  Enigma's semantic equivalent of Ghidra's entry-point pseudo
// reference is SymbolTable's external-entry-point list.
// ---------------------------------------------------------------------------

void GzfProgramImporter::importEntryPoints(ProgramDB* program) {
    const GbfTableSchema* refschema = reader_.findTable("FROM REFS");
    if (!refschema) {
        return;
    }
    SymbolTable* symbols = program->getSymbolTable();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!symbols || !space) {
        return;
    }
    // Record layout (RefListV0), same as the references phase: data
    // [int numRefs][binary ref data]; per ref [8B addrKey][1B flags][1B
    // refType][1B opIndex][+8B symbolId if 0x08][+8B offset if 0x04|0x10].
    reader_.visitRecords(*refschema, [&](const GbfRecord& rec) {
        const int64_t fromKey = keyToLong(rec.key);
        if (fromKey != -1 && fromKey != -2) {
            return;
        }
        if (rec.data.size() < 4) {
            return;
        }
        size_t off = 0;
        readBeNum(rec.data, off, 4);  // num refs
        std::vector<uint8_t> bin = readBeBinary(rec.data, off);
        size_t pos = 0;
        while (pos + 11 <= bin.size()) {
            const uint64_t toKey = static_cast<uint64_t>(readBeNum(bin, pos, 8));
            const uint8_t flags = static_cast<uint8_t>(bin[pos++]);
            pos += 2;  // refType, opIndex
            if (flags & REF_FLAG_HAS_SYMBOL_ID) pos += 8;
            if (flags & (REF_FLAG_OFFSET | REF_FLAG_SHIFT)) pos += 8;
            if ((toKey >> 32) != ADDR_KEY_IMAGE_SPACE) {
                continue;
            }
            symbols->addExternalEntryPoint(
                imageAddress(space, static_cast<uint64_t>(toKey) & 0xFFFFFFFFull));
            stats_.entryPoints++;
        }
    });
}

// ---------------------------------------------------------------------------
// Call fixups: "Property Map - CallFixup" — address key, [Value string].
// The engine's Function already carries callFixup (it feeds the decompiler's
// call-fixup handling); this map is the authoritative source for it.
// ---------------------------------------------------------------------------

void GzfProgramImporter::importCallFixups(ProgramDB* program) {
    for (const GbfTableSchema& t : reader_.tables()) {
        if (t.name != "Property Map - CallFixup" || t.isIndexTable()) {
            continue;
        }
        FunctionManager* mgr = program->getFunctionManager();
        AddressSpace* space = const_cast<AddressSpace*>(
            program->getAddressFactory()->getDefaultAddressSpace());
        if (!mgr || !space) {
            return;
        }
        reader_.visitRecords(t, [&](const GbfRecord& rec) {
            size_t off = 0;
            std::string fixup = readBeString(rec.data, off);
            if (fixup.empty()) {
                return;
            }
            Address addr(space, static_cast<int64_t>(keyToImageOffset(rec.key)));
            Function* func = mgr->getFunctionAt(addr);
            if (!func) {
                warn("call fixup '" + fixup + "' at 0x" +
                     toHexString(keyToImageOffset(rec.key)) + " has no function");
                return;
            }
            func->setCallFixup(fixup);
            stats_.callFixups++;
        });
        return;
    }
}

// ---------------------------------------------------------------------------
// Source maps: "SourceFiles" + "SourceMap" (DWARF-derived; key.exe/pro.exe).
// SourceFiles: key = file id; data [Path][IdType][Identifier].
// SourceMap: key = seq id; data [fileAndLine][baseAddress][length] where
// fileAndLine = (fileId << 32) | lineNumber and baseAddress is an
// address-map key in the image space.
// ---------------------------------------------------------------------------

void GzfProgramImporter::importSourceMaps(ProgramDB* program) {
    SourceFileManager* src = program->getSourceFileManager();
    AddressSpace* space =
        const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    if (!src || !space) {
        return;
    }
    std::map<int64_t, SourceFile*> filesById;
    for (const GbfTableSchema& t : reader_.tables()) {
        if (t.name != "SourceFiles" || t.isIndexTable()) {
            continue;
        }
        // SourceFiles' path column is sparse (nullable); it rides in
        // rec.sparseFields instead of rec.data.
        auto sparseString = [&t](const GbfRecord& rec, int col) {
            for (const auto& sf : rec.sparseFields) {
                if (sf.first != col) continue;
                size_t off = 0;
                return readBeString(sf.second, off);
            }
            return std::string();
        };
        reader_.visitRecords(t, [&](const GbfRecord& rec) {
            std::string path;
            if (std::find(t.sparseColumns.begin(), t.sparseColumns.end(), 0) !=
                t.sparseColumns.end()) {
                path = sparseString(rec, 0);
            } else {
                size_t off = 0;
                path = readBeString(rec.data, off);
            }
            if (path.empty()) {
                stats_.sourceMapBad++;
                return;
            }
            SourceFile* file = src->addSourceFile(path, "");
            if (!file) {
                stats_.sourceMapBad++;
                return;
            }
            filesById[keyToLong(rec.key)] = file;
            stats_.sourceFiles++;
        });
        break;
    }
    for (const GbfTableSchema& t : reader_.tables()) {
        if (t.name != "SourceMap" || t.isIndexTable()) {
            continue;
        }
        reader_.visitRecords(t, [&](const GbfRecord& rec) {
            size_t off = 0;
            const int64_t fileAndLine = readBeNum(rec.data, off, 8);
            const int64_t baseKey = readBeNum(rec.data, off, 8);
            const int64_t length = readBeNum(rec.data, off, 8);
            const int64_t fileId = fileAndLine >> 32;
            const int64_t line = fileAndLine & 0xFFFFFFFFull;
            auto fit = filesById.find(fileId);
            // length 0 is a legitimate DWARF marker (no address range);
            // only negative lengths are corrupt.
            if (fit == filesById.end() || line <= 0 ||
                (static_cast<uint64_t>(baseKey) >> 32) != ADDR_KEY_IMAGE_SPACE ||
                length < 0) {
                stats_.sourceMapBad++;
                static int shown2 = 0;
                if (shown2++ < 5) {
                    warn("srcmap reject: file=" + std::to_string(fileId) +
                         " line=" + std::to_string(line) +
                         " len=" + std::to_string(length) +
                         " base=0x" + toHexString(static_cast<uint64_t>(baseKey)));
                }
                return;
            }
            Address addr = imageAddress(space, static_cast<uint64_t>(baseKey) & 0xFFFFFFFFull);
            try {
                src->addSourceMapEntry(fit->second, static_cast<int>(line), addr,
                                       static_cast<uint64_t>(length));
            } catch (const std::exception& e) {
                // Overflowing/corrupt entry (e.g. length beyond the space):
                // count it bad instead of aborting the phase.
                stats_.sourceMapBad++;
                return;
            }
            stats_.sourceMapEntries++;
        });
        break;
    }
}

// ---------------------------------------------------------------------------
// Function variables: "Variable Storage" + variable symbols in "Symbols".
// Variable Storage: key = seq id; data [Hash][Storage string] where Storage
// is Ghidra's serialization — legacy "register:<hex>:<size>" /
// "stack:<hex>:<size>", Ghidra 12 bracket form "Stack[-0x4c]:4" (signed hex
// offset), or "<UNASSIGNED>"/"<VOID>"/"<BAD>".  Variable symbols (Symbol
// Type 6 = parameter, 7 = local) carry [Name][Address][Parent=function id]
// [Type][Flags] plus sparse columns Hash / Primary Datatype / Variable
// Offset (ordinal for parameters, first-use offset for locals).
// ---------------------------------------------------------------------------

void GzfProgramImporter::importVariables(ProgramDB* program) {
    const GbfTableSchema* symschema = reader_.findTable("Symbols");
    if (!symschema) {
        return;
    }
    ProgramContext* context = program->getProgramContext();
    auto* ctxImpl = dynamic_cast<ProgramContextImpl*>(context);
    AddressFactory* factory = program->getAddressFactory();
    if (!ctxImpl || !factory) {
        return;
    }

    // Register space for synthesized per-offset registers (storage strings
    // reference register offsets; names are language-derived and not stored
    // in the DB — same treatment as the references phase).
    AddressSpace* regSpace = const_cast<AddressSpace*>(factory->getRegisterSpace());
    if (!regSpace) {
        regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 0);
        if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
            paf->addAddressSpace(regSpace);
            paf->setRegisterSpace(regSpace);
        }
    }
    std::map<int64_t, Register*> registersByOffset;

    // Stack space: the imported program is language-less, so no stack space
    // exists yet, but Ghidra 12 stack storage ("Stack[-0x4c]:4") decodes
    // through the address factory against the registered stack space (mirror
    // of the snapshot reader's space set, same space id).
    if (!factory->getStackSpace()) {
        auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 4);
        if (auto* paf = dynamic_cast<ProgramAddressFactory*>(factory)) {
            paf->addAddressSpace(stackSpace);
            paf->setStackSpace(stackSpace);
        }
    }

    // Ghidra storage serialization -> engine VariableStorage.
    auto parseStorage = [&](const std::string& s) -> VariableStorage {
        if (s.empty() || s == "<UNASSIGNED>") return VariableStorage::UNASSIGNED_STORAGE;
        if (s == "<VOID>") return VariableStorage::VOID_STORAGE;
        if (s == "<BAD>") return VariableStorage::BAD_STORAGE;
        // Ghidra 12 serializes stack storage as "Stack[-0x4c]:4" (bracket
        // form, signed hex offset).  VariableStorage::deserialize routes the
        // piece through the address factory, which parses the bracket form
        // and (",")-joined compound pieces that the engine can represent, so
        // the exact offset and size are preserved; invalid data yields
        // BAD_STORAGE.
        if (s.find('[') != std::string::npos) {
            return VariableStorage::deserialize(program, s);
        }
        const auto first = s.find(':');
        const auto last = s.rfind(':');
        if (first == std::string::npos || last == first) {
            return VariableStorage::BAD_STORAGE;
        }
        const std::string spaceName = s.substr(0, first);
        const int64_t offset =
            std::strtoll(s.substr(first + 1, last - first - 1).c_str(), nullptr, 16);
        const int size = static_cast<int>(
            std::strtol(s.substr(last + 1).c_str(), nullptr, 10));
        if (size <= 0) {
            return VariableStorage::BAD_STORAGE;
        }
        if (spaceName == "register") {
            Register*& reg = registersByOffset[offset];
            if (!reg) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "r_0x%llx",
                              static_cast<unsigned long long>(offset));
                reg = ctxImpl->addOwnedRegister(std::make_unique<Register>(
                    buf, "", Address(regSpace, offset), size, false, 0));
            }
            return VariableStorage(program, std::vector<Register*>{reg});
        }
        if (spaceName == "stack") {
            return VariableStorage(program, static_cast<int>(offset), size);
        }
        return VariableStorage::BAD_STORAGE;
    };

    // "Variable Storage": record key -> storage string.  Ghidra links a
    // variable symbol to its storage record through the symbol's address:
    // variable symbols live in the "variable" address space whose offset IS
    // the storage record key (VariableStorageManagerDB
    // ::getVariableStorageAddress).  The stored Hash column is a CRC64 used
    // for record dedup only, not for lookup.
    std::unordered_map<int64_t, std::string> storageByKey;
    for (const GbfTableSchema& t : reader_.tables()) {
        if (t.name != "Variable Storage" || t.isIndexTable()) {
            continue;
        }
        reader_.visitRecords(t, [&](const GbfRecord& rec) {
            size_t off = 0;
            readBeNum(rec.data, off, 8);  // hash column (CRC64, dedup only)
            const std::string storage = readBeString(rec.data, off);
            storageByKey[keyToLong(rec.key)] = storage;
            stats_.variableStorages++;
        });
        break;
    }

    // Sparse-column positions, verified against raw record dumps: the
    // optional columns ride in rec.sparseFields keyed by column index —
    // 7 = "Primary" (datatype id, long), 8 = "Datatype" (ordinal for
    // parameters / first-use offset for locals, int).  (Column 5 "Hash" is
    // Ghidra's symbol locator hash, unrelated to storage lookup.)
    const int dtCol = 7;
    const int offCol = 8;
    auto sparseNum = [&](const GbfRecord& rec, int col, size_t width) -> int64_t {
        for (const auto& sf : rec.sparseFields) {
            if (sf.first != col) continue;
            size_t off = 0;
            return readBeNum(sf.second, off, width);
        }
        return INT64_MIN;
    };

    constexpr int SYMBOL_TYPE_PARAMETER = 6;
    constexpr int SYMBOL_TYPE_LOCAL_VAR = 7;
    reader_.visitRecords(*symschema, [&](const GbfRecord& rec) {
        size_t off = 0;
        std::string name = readBeString(rec.data, off);
        const int64_t address = readBeNum(rec.data, off, 8);
        const int64_t parent = readBeNum(rec.data, off, 8);
        const int type = static_cast<int>(readBeNum(rec.data, off, 1));
        const uint8_t flags = static_cast<uint8_t>(readBeNum(rec.data, off, 1));
        if (type != SYMBOL_TYPE_PARAMETER && type != SYMBOL_TYPE_LOCAL_VAR) {
            return;
        }
        auto fit = functionsById_.find(parent);
        if (fit == functionsById_.end() || !fit->second) {
            stats_.variablesBad++;
            warn("variable '" + name + "' references unknown function id " +
                 std::to_string(parent));
            return;
        }
        Function* func = fit->second;
        const int64_t dtId = sparseNum(rec, dtCol, 8);
        const int64_t varOff = sparseNum(rec, offCol, 4);
        // The symbol's address carries the storage record key: variable
        // symbols live in the variable address space (marker 0x60000000)
        // at offset == the "Variable Storage" record key.
        std::string storageStr;
        const uint64_t symAddr = static_cast<uint64_t>(address);
        if ((symAddr >> 32) == 0x60000000ull) {
            auto sit = storageByKey.find(static_cast<int64_t>(symAddr & 0xFFFFFFFFull));
            if (sit != storageByKey.end()) {
                storageStr = sit->second;
            }
        }
        VariableStorage storage = parseStorage(storageStr);
        DataType* dt = nullptr;
        if (dtId != INT64_MIN && dtId != 0) {
            dt = resolveDataType(dtId);
        }
        if (dt && storage.isValid() && dt->getLength() != storage.size()) {
            // Ghidra keeps a mismatched declared type and storage slot as-is
            // (DWARF location vs. declared byte size); the engine requires an
            // exact pair, so the declared type is dropped in favor of the
            // undefined-N derived from the storage size (Ghidra's own
            // typeless-variable convention) — the storage stays exact.
            dt = nullptr;
        }
        // A null datatype is Ghidra's null datatype (typeless hashed-storage
        // markers): the VariableImpl ctor derives undefined-N from the
        // storage size exactly as Ghidra does (Undefined.getUndefinedDataType
        // of the storage size), so no valid storage record is lost.
        const SourceType source = decodeSourceType(flags);
        if (type == SYMBOL_TYPE_PARAMETER) {
            const int ordinal = varOff == INT64_MIN ? -1 : static_cast<int>(varOff);
            auto* param = new ParameterImpl(name, ordinal, dt, storage, program, source);
            func->addParameter(param);
            stats_.parameters++;
        } else {
            const int firstUse = varOff == INT64_MIN ? 0 : static_cast<int>(varOff);
            auto* var =
                new LocalVariableImpl(name, firstUse, dt, storage, program, source);
            func->addLocalVariable(var);
            stats_.localVariables++;
        }
    });
}

// ---------------------------------------------------------------------------
// Metadata: "Metadata" (ProgramMetadataManager)
// ---------------------------------------------------------------------------
// The table key is a long db id; the [Key string][Value string] pair is the
// record data.
void GzfProgramImporter::importMetadata(ProgramDB* program) {
    const GbfTableSchema* t = reader_.findTable("Metadata");
    if (!t) {
        return;
    }
    reader_.visitRecords(*t, [&](const GbfRecord& rec) {
        size_t off = 0;
        std::string key = readBeString(rec.data, off);
        std::string value = readBeString(rec.data, off);
        program->setMetadata(key, value);
        stats_.metadataRecords++;
    });
}

}  // namespace ghidra
