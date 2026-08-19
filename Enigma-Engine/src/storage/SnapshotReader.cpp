#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/StackReference.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/EquateTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/Relocation.h>
#include <ghidra/RelocationTableImpl.h>
#include <ghidra/FunctionTagManager.h>
#include <ghidra/FunctionTag.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataOrganizationImpl.h>
#include <ghidra/GenericDataType.h>
#include <ghidra/DataType.h>
#include <ghidra/Composite.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/BuiltIn.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/IBO32DataType.h>
#include <ghidra/IBO64DataType.h>
#include <ghidra/CharDataType.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/UnsignedCharDataType.h>
#include <ghidra/Undefined1DataType.h>
#include <ghidra/Undefined2DataType.h>
#include <ghidra/Undefined3DataType.h>
#include <ghidra/Undefined4DataType.h>
#include <ghidra/Undefined5DataType.h>
#include <ghidra/Undefined6DataType.h>
#include <ghidra/Undefined7DataType.h>
#include <ghidra/Undefined8DataType.h>
#include <ghidra/UnicodeDataType.h>
#include <ghidra/WideChar16DataType.h>
#include <ghidra/WideCharDataType.h>
#include <ghidra/TerminatedStringDataType.h>
#include <ghidra/TerminatedUnicodeDataType.h>
#include <ghidra/TerminatedUnicode32DataType.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/LocalVariableImpl.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/TreeManager.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/ModuleDB.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/RefType.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/Register.h>
#include "program_generated.h"
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <vector>
#include <map>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>

namespace ghidra {
namespace storage {

namespace fb = fbschema;

// Placeholder builtin for snapshot builtin classes the engine does not
// implement (mirrors GzfProgramImporter::PlaceholderDataType).  Carries the
// serialized description so round-trips stay byte-identical.
class SnapshotPlaceholderDataType : public BuiltIn {
public:
    SnapshotPlaceholderDataType(DataTypeManager* dtm, const std::string& name, int length,
                                std::string description = "")
        : BuiltIn(CategoryPath::ROOT(), name, dtm),
          length_(length),
          description_(std::move(description)) {}
    int getLength() const override { return length_; }
    int getAlignedLength() const override { return length_; }
    bool hasLanguageDependantLength() const override { return length_ <= 0; }
    DataType* clone(DataTypeManager* dtm) const override {
        return new SnapshotPlaceholderDataType(dtm, getName(), length_, description_);
    }
    DataType* copy(DataTypeManager* dtm) const override {
        return new SnapshotPlaceholderDataType(dtm, getName(), length_, description_);
    }
    std::string getDescription() const override {
        return description_.empty()
                   ? "Placeholder for a builtin class not implemented by the engine"
                   : description_;
    }
    std::string getMnemonic(Settings* /*settings*/) const override { return getName(); }
    std::string getRepresentation(MemBuffer* /*buf*/, Settings* /*settings*/,
                                  int /*length*/) const override {
        return getName();
    }
    const std::type_info& getValueClass(Settings* /*settings*/) const override {
        return typeid(void*);
    }
    bool isEquivalent(const DataType* dt) const override {
        return dt && dt->getLength() == length_ && dt->getName() == getName();
    }
    std::string getDefaultLabelPrefix() const override { return getName(); }
private:
    int length_;
    std::string description_;
};

// Reconstruct real engine builtin classes from their canonical names so
// reloaded types carry the genuine class behavior and description (mirrors
// the importer's class map).  Names the engine lacks fall back to a
// description-carrying placeholder, keeping round-trips byte-identical.
DataType* makeBuiltinByName(const std::string& name, int length, DataTypeManager* dtm,
                            const std::string& serializedDesc) {
    DataType* dt = nullptr;
    if (name == "char") dt = new CharDataType(dtm);
    else if (name == "undefined") dt = new DefaultDataType();
    else if (name == "word") dt = new WordDataType(dtm);
    else if (name == "dword") dt = new DWordDataType(dtm);
    else if (name == "qword") dt = new QWordDataType(dtm);
    else if (name == "uchar") dt = new UnsignedCharDataType(dtm);
    else if (name == "undefined1") dt = new Undefined1DataType(dtm);
    else if (name == "undefined2") dt = new Undefined2DataType(dtm);
    else if (name == "undefined3") dt = new Undefined3DataType(dtm);
    else if (name == "undefined4") dt = new Undefined4DataType(dtm);
    else if (name == "undefined5") dt = new Undefined5DataType(dtm);
    else if (name == "undefined6") dt = new Undefined6DataType(dtm);
    else if (name == "undefined7") dt = new Undefined7DataType(dtm);
    else if (name == "undefined8") dt = new Undefined8DataType(dtm);
    else if (name == "unicode") dt = new UnicodeDataType(dtm);
    else if (name == "wchar16") dt = new WideChar16DataType(dtm);
    else if (name == "wchar_t") dt = new WideCharDataType(dtm);
    else if (name == "TerminatedCString") dt = new TerminatedStringDataType(dtm);
    else if (name == "TerminatedUnicode") dt = new TerminatedUnicodeDataType(dtm);
    else if (name == "TerminatedUnicode32") dt = new TerminatedUnicode32DataType(dtm);
    if (dt) return dt;
    return new SnapshotPlaceholderDataType(dtm, name, length, serializedDesc);
}

// Compact storage parser (mirror of SnapshotWriter::storageToString):
// "u" | "reg:<offset>:<size>" | "stack:<signedOffset>:<size>" |
// "mem:<offset>:<size>".
VariableStorage parseStorage(Program* program, ProgramContextImpl* ctx,
                             AddressSpace* regSpace,
                             std::map<int64_t, Register*>& regCache,
                             const std::string& s) {
    if (s.empty() || s == "u") return VariableStorage::UNASSIGNED_STORAGE;
    const auto c1 = s.find(':');
    const auto c2 = s.rfind(':');
    if (c1 == std::string::npos || c2 == c1) return VariableStorage::UNASSIGNED_STORAGE;
    const std::string kind = s.substr(0, c1);
    const int64_t a = std::strtoll(s.substr(c1 + 1, c2 - c1 - 1).c_str(), nullptr, 10);
    const int size = static_cast<int>(std::strtol(s.substr(c2 + 1).c_str(), nullptr, 10));
    if (size <= 0) return VariableStorage::UNASSIGNED_STORAGE;
    if (kind == "reg") {
        if (!ctx || !regSpace) return VariableStorage::UNASSIGNED_STORAGE;
        Register*& reg = regCache[a];
        if (!reg) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "r_%llx",
                          static_cast<unsigned long long>(a));
            reg = ctx->addOwnedRegister(std::make_unique<Register>(
                buf, "", Address(regSpace, a), size, /*bigEndian=*/false, 0));
        }
        return VariableStorage(program, std::vector<Register*>{reg});
    }
    if (kind == "stack") {
        return VariableStorage(program, static_cast<int>(a), size);
    }
    if (kind == "mem" && program->getAddressFactory() &&
        program->getAddressFactory()->getDefaultAddressSpace()) {
        Address addr(const_cast<AddressSpace*>(
                         program->getAddressFactory()->getDefaultAddressSpace()),
                     a);
        return VariableStorage(program, addr, size);
    }
    return VariableStorage::UNASSIGNED_STORAGE;
}

// RefType value bytes (RefType.java) -> static instances (RefTypes);
// mirrors GzfProgramImporter::refTypeByValue.
static const RefType* refTypeByValue(int8_t v) {
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

std::vector<uint8_t> SnapshotReader::readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Cannot open snapshot: " + path);
    size_t size = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::vector<uint8_t> data(size);
    if (!in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size)))
        throw std::runtime_error("Failed to read snapshot: " + path);
    return data;
}

void SnapshotReader::validateSchemaVersion(const uint8_t* data, size_t size) {
    flatbuffers::Verifier verifier(data, size);
    if (!verifier.VerifyBuffer<fb::ProgramSnapshot>(nullptr)) {
        throw std::runtime_error("Snapshot verification failed: corrupt data");
    }
    auto snapshot = flatbuffers::GetRoot<fb::ProgramSnapshot>(data);
    int version = snapshot->schema_version();
    if (version != 1) {
        throw std::runtime_error("Unsupported schema version: " + std::to_string(version));
    }
}

std::unique_ptr<ProgramDB> SnapshotReader::deserialize(const uint8_t* data, size_t size) {
    validateSchemaVersion(data, size);
    auto snapshot = flatbuffers::GetRoot<fb::ProgramSnapshot>(data);

    std::string binaryName = snapshot->binary_name() ? snapshot->binary_name()->str() : "";
    auto program = std::make_unique<ProgramDB>(binaryName, nullptr, nullptr);

    if (!binaryName.empty()) program->setName(binaryName);
    if (snapshot->language_id())
        program->setLanguageID(LanguageID(snapshot->language_id()->str()));
    if (snapshot->compiler_spec_id())
        program->setCompilerSpecID(CompilerSpecID(snapshot->compiler_spec_id()->str()));

    // Address spaces (mirrors the importer's space set; the EXTERNAL space is
    // required for external symbols/locations and external references).
    AddressSpace* ramSpace = nullptr;
    AddressSpace* regSpace = nullptr;
    AddressSpace* externalSpace = nullptr;
    {
        auto* af = dynamic_cast<ProgramAddressFactory*>(program->getAddressFactory());
        if (af) {
            ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 0);
            auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 1);
            auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 2);
            regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 3);
            auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 4);
            externalSpace = new GenericAddressSpace("EXTERNAL", 64, AddressSpace::TYPE_EXTERNAL, 5);
            af->addAddressSpace(ramSpace);
            af->addAddressSpace(constSpace);
            af->addAddressSpace(uniqueSpace);
            af->addAddressSpace(regSpace);
            af->addAddressSpace(stackSpace);
            af->addAddressSpace(externalSpace);
            af->setDefaultSpace(ramSpace);
            af->setRegisterSpace(regSpace);
            af->setStackSpace(stackSpace);
        }
    }

    // Helpers for variable-storage restoration (owned registers by offset).
    ProgramContextImpl* ctxHelper =
        dynamic_cast<ProgramContextImpl*>(program->getProgramContext());
    std::map<int64_t, Register*> varRegCache;

    bool bigEndian = snapshot->is_big_endian();

    // Memory blocks with bytes, permissions and comments.
    if (auto* memBlocks = snapshot->memory_blocks()) {
        if (memBlocks->size() > 0) {
            auto defaultMem = std::make_unique<DefaultMemory>(bigEndian);
            for (auto* fbBlock : *memBlocks) {
                std::string name = fbBlock->name() ? fbBlock->name()->str() : "";
                Address start(ramSpace, static_cast<int64_t>(fbBlock->start_address()));
                long long size = static_cast<long long>(fbBlock->length());
                auto* bytes = fbBlock->bytes();
                MemoryBlock* block = nullptr;
                if (bytes && bytes->size() > 0) {
                    block = defaultMem->createInitializedBlock(name, start, size, false);
                    if (block) {
                        int writeSize = static_cast<int>(std::min<uint64_t>(
                            static_cast<uint64_t>(bytes->size()), fbBlock->length()));
                        defaultMem->setBytes(start, bytes->data(), writeSize);
                    }
                } else {
                    block = defaultMem->createUninitializedBlock(name, start, size, false);
                }
                if (block) {
                    if (fbBlock->permissions()) {
                        const char* perm = fbBlock->permissions()->c_str();
                        bool r = perm[0] != '\0' && perm[0] != '-';
                        bool w = perm[1] != '\0' && perm[1] != '-';
                        bool x = perm[2] != '\0' && perm[2] != '-';
                        block->setPermissions(r, w, x);
                    }
                    if (fbBlock->comment()) {
                        block->setComment(fbBlock->comment()->str());
                    }
                }
            }
            program->setMemory(defaultMem.release());
        }
    }

    if (snapshot->image_base() != 0)
        program->setImageBase(Address(ramSpace, static_cast<int64_t>(snapshot->image_base())));
    if (snapshot->min_address() != 0 || snapshot->max_address() != 0) {
        program->setMinAddress(Address(ramSpace, static_cast<int64_t>(snapshot->min_address())));
        program->setMaxAddress(Address(ramSpace, static_cast<int64_t>(snapshot->max_address())));
    }

    // Data organization settings (pointer size, machine alignment, MS
    // bitfield convention, size-alignment table) — restored before datatypes
    // so alignment-derived computations see the corpus values.
    if (auto* org = snapshot->data_org()) {
        if (auto* dtmOrg = dynamic_cast<DataOrganizationImpl*>(
                program->getDataTypeManager()->getDataOrganization())) {
            if (org->pointer_size() > 0) dtmOrg->setPointerSize(org->pointer_size());
            if (org->machine_alignment() > 0) {
                dtmOrg->setMachineAlignment(org->machine_alignment());
            }
            dtmOrg->setUseMSConvention(org->use_ms_convention());
            if (auto* entries = org->size_alignments()) {
                for (auto* e : *entries) {
                    if (e && e->size() > 0 && e->alignment() > 0) {
                        dtmOrg->setSizeAlignment(e->size(), e->alignment());
                    }
                }
            }
        }
    }

// -----------------------------------------------------------------------
    // Data types: id map + full restore (categories, pack, field offsets,
    // bitfields, function definitions).
    // -----------------------------------------------------------------------
std::map<uint64_t, DataType*> idMap;
    auto* dtm = program->getDataTypeManager();
    auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtm);
    if (dtm && dtmImpl) {
        for (auto* dt : dtm->getDataTypes()) {
            long id = dtmImpl->getDataTypeId(dt);
            if (id > 0) idMap[static_cast<uint64_t>(id)] = dt;
        }

        struct TypeEntry { DataType* dt = nullptr; std::string kind; const fb::DataTypeRecord* fbDt = nullptr; };
        std::vector<TypeEntry> pending;

        // Pass A: name-matched alias (fresh builtins, e.g. engine "int" for
        // the corpus "int" record; ids then map through the same mechanism
        // the importer used).
        if (auto* dataTypes = snapshot->data_types()) {
            for (auto* fbDt : *dataTypes) {
                std::string name = fbDt->name() ? fbDt->name()->str() : "";
                uint64_t dtId = fbDt->dt_id();
                if (name.empty() || dtId == 0) continue;
                std::string pathStr = fbDt->category_path() ? fbDt->category_path()->str() : "/";
                CategoryPath path;
                try {
                    path = CategoryPath(pathStr);
                } catch (const std::invalid_argument&) {
                    path = CategoryPath::ROOT();
                }
                DataType* existing = dtmImpl->getDataType(path, name);
                if (existing) {
                    idMap[dtId] = existing;
                    continue;
                }
            }

            // Pass B: create shells (deferred kinds resolved iteratively).
            bool progress = true;
            while (progress) {
                progress = false;
                for (auto* fbDt : *dataTypes) {
                    std::string name = fbDt->name() ? fbDt->name()->str() : "";
                    uint64_t dtId = fbDt->dt_id();
                    if (name.empty() || dtId == 0) continue;
if (idMap.find(dtId) != idMap.end()) continue;
                    std::string typeKind = fbDt->type_kind() ? fbDt->type_kind()->str() : "";
                    std::string pathStr = fbDt->category_path() ? fbDt->category_path()->str() : "/";
                    CategoryPath path;
                    try {
                        path = CategoryPath(pathStr);
                    } catch (const std::invalid_argument&) {
                        path = CategoryPath::ROOT();
                    }
                    int size = fbDt->size();
                    DataType* newDt = nullptr;
                    bool deferred = false;
                    if (typeKind == "struct") {
                        newDt = new StructureDataType(path, name, 0, dtmImpl);
                    } else if (typeKind == "union") {
                        newDt = new UnionDataType(path, name, dtmImpl);
                    } else if (typeKind == "enum") {
                        newDt = new EnumDataType(path, name, size, dtmImpl);
                    } else if (typeKind == "function") {
                        newDt = new FunctionDefinitionDataType(path, name, nullptr, dtmImpl);
                    } else if (typeKind == "builtin") {
                        std::string desc =
                            fbDt->description() ? fbDt->description()->str() : "";
                        newDt = makeBuiltinByName(name, size, dtmImpl, desc);
} else if (typeKind == "pointer") {
                        uint64_t targetId = fbDt->pointer_target_id();
                        if (targetId == 0) {
                            newDt = new PointerDataType(nullptr, size, dtmImpl);
                        } else {
                            auto it = idMap.find(targetId);
                            if (it != idMap.end()) {
                                newDt = new PointerDataType(it->second, size, dtmImpl);
                            } else {
                                deferred = true;
                            }
                        }
                    } else if (typeKind == "array") {
                        uint64_t elemId = fbDt->array_element_id();
                        auto it = idMap.find(elemId);
                        if (it != idMap.end()) {
                            int count = fbDt->array_element_count();
                            // Zero-element arrays are legal (flexible array
                            // members); ArrayDataType models their length as 1.
                            newDt = new ArrayDataType(it->second, count, -1, dtmImpl);
                        } else {
                            deferred = true;
                        }
                    } else if (typeKind == "typedef") {
                        if (name == "ImageBaseOffset32") {
                            // Engine pointer-typedef builtin with its own
                            // internal base; the generic typedef path would
                            // lose its description/behavior.
                            newDt = new IBO32DataType(dtmImpl);
                        } else if (name == "ImageBaseOffset64") {
                            newDt = new IBO64DataType(dtmImpl);
                        } else {
                            uint64_t baseId = fbDt->typedef_base_id();
                            auto it = idMap.find(baseId);
                            if (it != idMap.end()) {
                                newDt = new TypedefDataType(path, name, it->second, dtmImpl);
                            } else {
                                deferred = true;
                            }
                        }
                    }
if (newDt) {
                        if (fbDt->inline_materialized()) {
                            // Writer-materialized helper (an intentionally
                            // unregistered type the source program still
                            // references).  Adopt it as an orphan unless a
                            // registered type already claims the same path —
                            // then the helper is redundant and its references
                            // must resolve to the registered instance.
                            DataType* existing = dtmImpl->getDataType(path, name);
                            if (existing && existing != newDt) {
                                delete newDt;
                                newDt = existing;
                            } else {
                                dtmImpl->adoptOrphanDataType(newDt);
                            }
                        } else {
                            DataType* registered =
                                dtmImpl->addDataTypeWithId(newDt,
                                                           static_cast<int64_t>(dtId));
                            if (registered && registered != newDt) {
                                // Path conflict: the manager kept a
                                // previously-registered type.  The fresh
                                // shell never entered the manager and owns
                                // nothing; drop it and reference the
                                // registered instance instead.
                                delete newDt;
                                newDt = registered;
                            }
                        }
                        idMap[dtId] = newDt;
                        pending.push_back({newDt, typeKind, fbDt});
                        progress = true;
                    } else if (deferred) {
                        pending.push_back({nullptr, typeKind, fbDt});
                    }
                }
            }

            // Pass C0: apply recorded lengths to structure shells first so
            // fields whose types are composites resolve their true component
            // length — a length-0 shell would otherwise collapse to a
            // zero-length component under the flexible-array rule.
            for (auto& entry : pending) {
                if (!entry.dt || entry.fbDt->size() <= 0) continue;
                if (entry.kind == "struct") {
                    if (auto* st = dynamic_cast<StructureDataType*>(entry.dt)) {
                        st->setLength(entry.fbDt->size());
                    }
                }
            }

            // Pass C: fill fields, enum values, function definitions, packing.
            for (auto& entry : pending) {
                if (!entry.dt) continue;
                // Named user-managed types (GenericDataType) take the
                // recorded description; builtins/pointers and the IBO
                // typedef special-cases have immutable computed ones.
                if (auto* gd = dynamic_cast<GenericDataType*>(entry.dt)) {
                    if (entry.fbDt->description()) {
                        gd->setDescription(entry.fbDt->description()->str());
                    }
                }
                if (entry.kind == "struct") {
                    if (auto* fields = entry.fbDt->fields()) {
                        auto* st = dynamic_cast<StructureDataType*>(entry.dt);
                        if (st) {
                            for (auto* field : *fields) {
                                std::string fn = field->name() ? field->name()->str() : "";
                                const bool isBitField = field->bit_size() > 0;
                                DataType* ft = nullptr;
                                if (!isBitField) {
                                    // Bitfield components carry no
                                    // data_type_id (the base type travels in
                                    // bit_base_id); only plain fields resolve
                                    // through data_type_id.
                                    auto fit = idMap.find(field->data_type_id());
                                    ft = (fit != idMap.end()) ? fit->second : nullptr;
                                    if (!ft) continue;
                                }
                                int offset = field->offset();
                                int byteWidth = field->size();
                                if (isBitField) {
                                    auto bit =
                                        idMap.find(static_cast<uint64_t>(field->bit_base_id()));
                                    if (bit != idMap.end()) {
                                        st->insertBitFieldAt(offset, byteWidth,
                                                             field->bit_offset(),
                                                             bit->second, field->bit_size(),
                                                             fn, field->comment() ? field->comment()->str() : "");
                                    }
                                } else {
                                    // byteWidth 0 is legal (zero-length array
                                    // fields, e.g. flexible members).
                                    st->insertAtOffset(offset, ft, byteWidth, fn,
                                                       field->comment() ? field->comment()->str() : "");
                                }
                            }
                            st->setLength(entry.fbDt->size());
                        }
                    }
                } else if (entry.kind == "union") {
                    if (auto* fields = entry.fbDt->fields()) {
                        auto* un = dynamic_cast<UnionDataType*>(entry.dt);
                        if (un) {
                            int ordinal = 0;
                            for (auto* field : *fields) {
                                std::string fn = field->name() ? field->name()->str() : "";
                                uint64_t ftId = field->data_type_id();
                                auto fit = idMap.find(ftId);
                                DataType* ft = (fit != idMap.end()) ? fit->second : nullptr;
                                if (!ft) { ordinal++; continue; }
                                if (field->bit_size() > 0) {
                                    auto bit = idMap.find(static_cast<uint64_t>(field->bit_base_id()));
                                    if (bit == idMap.end()) { ordinal++; continue; }
                                    auto* bf = new BitFieldDataType(bit->second,
                                                                    field->bit_size(),
                                                                    field->bit_offset());
                                    auto* dc = un->insert(ordinal, bf, field->size(), fn,
                                                          field->comment() ? field->comment()->str() : "");
                                    if (auto* concrete = dynamic_cast<DataTypeComponentImpl*>(dc)) {
                                        concrete->setOwnsDataType(true);
                                    }
                                } else {
                                    un->insert(ordinal, ft, field->size(), fn,
                                               field->comment() ? field->comment()->str() : "");
                                }
                                ordinal++;
                            }
                        }
                    }
                } else if (entry.kind == "enum") {
                    if (auto* evs = entry.fbDt->enum_values()) {
                        auto* en = dynamic_cast<EnumDataType*>(entry.dt);
                        if (en) {
                            for (auto* ev : *evs) {
                                en->add(ev->name() ? ev->name()->str() : "",
                                        ev->value(),
                                        ev->comment() ? ev->comment()->str() : "");
                            }
                        }
                    }
                } else if (entry.kind == "function") {
                    auto* f = dynamic_cast<FunctionDefinitionDataType*>(entry.dt);
                    if (f) {
                        std::vector<ParameterDefinition*> params;
                        if (auto* fields = entry.fbDt->fields()) {
                            for (auto* field : *fields) {
                                uint64_t ftId = field->data_type_id();
                                auto fit = idMap.find(ftId);
                                DataType* ft = (fit != idMap.end()) ? fit->second : nullptr;
                                if (!ft) continue;
                                params.push_back(new ParameterDefinitionImpl(
                                    field->name() ? field->name()->str() : "",
                                    ft, field->comment() ? field->comment()->str() : "",
                                    field->offset()));
                            }
                        }
                        std::sort(params.begin(), params.end(),
                                  [](const ParameterDefinition* a, const ParameterDefinition* b) {
                                      return a->getOrdinal() < b->getOrdinal();
                                  });
                        f->setArguments(params);
                        if (entry.fbDt->funcdef_varargs()) {
                            f->setVarArgs(true);
                        }
                        uint64_t retId = entry.fbDt->pointer_target_id();
                        auto rit = idMap.find(retId);
                        if (rit != idMap.end()) {
                            f->setReturnType(rit->second);
                        }
                    }
                }
                if (auto* comp = dynamic_cast<Composite*>(entry.dt)) {
                    int pack = entry.fbDt->pack();
                    if (pack == 0) {
                        comp->setPackingEnabled(true);
                    } else if (pack > 0) {
                        comp->setExplicitPackingValue(pack);
                    }
                    int minAlign = entry.fbDt->min_alignment();
                    if (minAlign > 0) {
                        comp->setExplicitMinimumAlignment(minAlign);
                    }
                }
            }

            // Arrays capture their element length at construction, which may
            // predate the element's own length fixup above; recompute it from
            // the serialized total size now that all elements are final.
            for (auto& entry : pending) {
                if (!entry.dt || entry.kind != "array") continue;
                if (auto* arr = dynamic_cast<ArrayDataType*>(entry.dt)) {
                    int count = entry.fbDt->array_element_count();
                    if (count > 0) {
                        arr->setElementLength(entry.fbDt->size() / count);
                    }
                }
            }
        }
    }

// -----------------------------------------------------------------------
    // Code units (instructions + data) then comments.
    // -----------------------------------------------------------------------
    auto* listing = program->getListing();
    if (listing) {
        if (auto* units = snapshot->code_units()) {
            for (auto* fbUnit : *units) {
                Address addr(ramSpace, static_cast<int64_t>(fbUnit->address()));
                std::string unitType = fbUnit->unit_type() ? fbUnit->unit_type()->str() : "";
                if (unitType == "instruction") {
                    std::string mnemonic = fbUnit->mnemonic() ? fbUnit->mnemonic()->str() : "";
                    if (mnemonic.empty()) continue;
                    auto* inst = new Instruction(program.get(), addr, mnemonic,
                                                 fbUnit->length(), nullptr);
                    listing->addInstruction(inst);
} else {
                    DataType* dt = nullptr;
                    if (fbUnit->data_type_id() > 0) {
                        auto it = idMap.find(fbUnit->data_type_id());
                        if (it != idMap.end()) dt = it->second;
                    }
                    if (!dt && fbUnit->data_type_name()) {
                        dt = dtm ? dtm->getDataType(CategoryPath::ROOT(),
                                                   fbUnit->data_type_name()->str()) : nullptr;
                    }
                    if (!dt) dt = &ByteDataType::dataType();
                    int length = fbUnit->data_length() > 0
                                     ? fbUnit->data_length()
                                     : fbUnit->length();
                    listing->createData(addr, dt, length);
                }
            }
        }
        if (auto* cmts = snapshot->comments()) {
            for (auto* fbCmt : *cmts) {
                Address addr(ramSpace, static_cast<int64_t>(fbCmt->address()));
                CodeUnit* cu = listing->getCodeUnitAt(addr);
                if (!cu) {
                    cu = listing->createData(addr, &ByteDataType::dataType(), 1);
                }
                if (!cu) continue;
                std::string text = fbCmt->text() ? fbCmt->text()->str() : "";
                std::string slot = fbCmt->comment_type() ? fbCmt->comment_type()->str() : "";
                if (slot == "PRE") cu->setPreComment(text);
                else if (slot == "POST") cu->setPostComment(text);
                else if (slot == "PLATE") cu->setPlateComment(text);
                else if (slot == "REPEATABLE") cu->setRepeatableComment(text);
                else cu->setComment(text);
            }
        }
    }

// -----------------------------------------------------------------------
    // Symbols: namespaces, memory labels, external symbols/locations.
    // FUNCTION/THUNK symbols are created by the function restore below.
    // -----------------------------------------------------------------------
auto* st = program->getSymbolTable();
    auto* em = program->getExternalManager();
    long nextNamespaceId = -1;
    auto ensureNamespace = [&](const std::string& path) -> Namespace* {
        if (path.empty()) return st->getGlobalNamespace();
        Namespace* current = st->getGlobalNamespace();
        size_t pos = 0;
        while (pos <= path.size()) {
            size_t end = path.find("::", pos);
            if (end == std::string::npos) end = path.size();
            std::string segment = path.substr(pos, end - pos);
            if (segment.empty()) return current;
            const auto& nsMap = st->getNamespaces();
            Namespace* child = nullptr;
            for (const auto& kv : nsMap) {
                if (kv.second && kv.second->getParent() == current &&
                    kv.second->getName() == segment) {
                    child = kv.second.get();
                    break;
                }
            }
            if (!child) {
                child = st->addNamespaceWithId(nextNamespaceId--, segment, current);
            }
            current = child;
            if (end == path.size()) break;
            pos = end + 2;
        }
        return current;
    };
    if (auto* syms = snapshot->symbols()) {
        for (auto* fbSym : *syms) {
            std::string name = fbSym->name() ? fbSym->name()->str() : "";
            if (name.empty()) continue;
            std::string type = fbSym->symbol_type() ? fbSym->symbol_type()->str() : "";
            std::string nsPath = fbSym->parent_namespace() ? fbSym->parent_namespace()->str() : "";
            uint64_t key = fbSym->address();
            const uint64_t extMask = 0x5000000000000000ull;
            if ((key >> 32) == 0x50000000) {
                Namespace* ns = ensureNamespace(nsPath);
                Address addr(externalSpace, static_cast<int64_t>(key & 0xFFFFFFFFull));
                Symbol* sym = st->createExternalSymbol(nextNamespaceId--, name, addr, ns,
                                                       SourceType::DEFAULT, type == "FUNCTION");
                if (sym && fbSym->symbol_source() > 0) {
                    sym->setSource(static_cast<SourceType>(fbSym->symbol_source()));
                }
                if (em) {
                    em->addExternalLocation(nsPath, name, addr, nextNamespaceId + 1, "",
                                            type == "FUNCTION");
                }
            } else {
                if (type == "FUNCTION" || type == "THUNK") continue;
                Namespace* ns = ensureNamespace(nsPath);
                Address addr(ramSpace, static_cast<int64_t>(key));
                Symbol* sym = st->createLabel(addr, name, ns, SourceType::DEFAULT);
                if (sym) {
                    sym->setPrimary(fbSym->is_primary());
                    if (fbSym->symbol_source() > 0) {
                        sym->setSource(static_cast<SourceType>(fbSym->symbol_source()));
                    }
                }
            }
        }
    }

// -----------------------------------------------------------------------
    // Functions (+ thunk linkage pass).
    // -----------------------------------------------------------------------
    std::vector<std::pair<uint64_t, uint64_t>> thunkPairs;  // (entry, thunked entry)
    if (auto* funcs = snapshot->functions()) {
        auto* fm = program->getFunctionManager();
        if (fm) {
            if (auto* fbConvs = snapshot->calling_conventions()) {
                for (auto* fbCc : *fbConvs) {
                    std::string ccName = fbCc->name() ? fbCc->name()->str() : "";
                    if (ccName.empty() || fm->getCallingConvention(ccName)) continue;
                    fm->addCallingConvention(ccName,
                        std::make_unique<PrototypeModel>(ccName, ccName, false));
                }
            }
for (auto* fbFunc : *funcs) {
                std::string name = fbFunc->name() ? fbFunc->name()->str() : "";
if (name.empty()) continue;
                Address entry(ramSpace, static_cast<int64_t>(fbFunc->entry_point()));
                AddressSet body;
                if (auto* ranges = fbFunc->body_ranges()) {
                    for (auto* range : *ranges) {
                        Address start(ramSpace, static_cast<int64_t>(range->offset()));
                        body.addRange(start, start.add(static_cast<int64_t>(range->length()) - 1));
                    }
                }
                // Create with an empty body, then apply the serialized body
                // directly (the importer's pattern): corpus scope maps can
                // legitimately hold ranges createFunction's overlap check
                // would reject, and the snapshot must restore them verbatim.
                Function* func = fm->createFunction(name, entry, AddressSet(),
                                                    SourceType::DEFAULT);
                if (!func) continue;
                if (!body.isEmpty()) {
                    func->setBody(body);
                }
                func->setStackFrameSize(static_cast<int>(fbFunc->stack_frame_size()));
                if (fbFunc->has_no_return()) func->setHasNoReturn(true);
                if (fbFunc->is_inline()) func->setInline(true);
                if (fbFunc->is_external()) func->setExternal(true);
                if (fbFunc->call_fixup()) func->setCallFixup(fbFunc->call_fixup()->str());
                func->setSignatureSource(static_cast<SignatureSource>(fbFunc->signature_source()));
                if (fbFunc->calling_convention()) {
                    PrototypeModel* cc = fm->getCallingConvention(fbFunc->calling_convention()->str());
                    if (cc) func->setCallingConvention(cc);
                }
                if (fbFunc->return_type_id() > 0) {
                    auto typeIt = idMap.find(fbFunc->return_type_id());
                    if (typeIt != idMap.end()) func->setReturnType(typeIt->second);
                } else if (fbFunc->return_type()) {
                    DataType* retDt = dtm ? dtm->getDataType(CategoryPath::ROOT(),
                                                            fbFunc->return_type()->str()) : nullptr;
                    if (retDt) func->setReturnType(retDt);
                }
                if (auto* fbParams = fbFunc->params()) {
                    for (auto* fbParam : *fbParams) {
                        std::string pname = fbParam->name() ? fbParam->name()->str() : "";
                        DataType* dt = nullptr;
                        if (fbParam->data_type_id() > 0) {
                            auto typeIt = idMap.find(fbParam->data_type_id());
                            if (typeIt != idMap.end()) dt = typeIt->second;
                        } else if (fbParam->data_type_name()) {
                            dt = dtm ? dtm->getDataType(CategoryPath::ROOT(),
                                                       fbParam->data_type_name()->str()) : nullptr;
                        }
if (dt) {
                            std::string storageStr =
                                fbParam->storage() ? fbParam->storage()->str() : "u";
                            auto* param = new ParameterImpl(
                                pname, fbParam->ordinal(), dt,
                                parseStorage(program.get(), ctxHelper, regSpace, varRegCache, storageStr),
                                program.get());
                            func->addParameter(param);
                        }
                    }
                }
                if (auto* fbLocals = fbFunc->locals()) {
                    for (auto* fbLocal : *fbLocals) {
                        std::string lname = fbLocal->name() ? fbLocal->name()->str() : "";
                        DataType* dt = nullptr;
                        if (fbLocal->data_type_id() > 0) {
                            auto typeIt = idMap.find(fbLocal->data_type_id());
                            if (typeIt != idMap.end()) dt = typeIt->second;
                        }
if (!dt) continue;
                        std::string storageStr =
                            fbLocal->storage() ? fbLocal->storage()->str() : "u";
                        auto* var = new LocalVariableImpl(
                            lname, fbLocal->first_use_offset(), dt,
                            parseStorage(program.get(), ctxHelper, regSpace, varRegCache, storageStr),
                            program.get());
                        func->addLocalVariable(var);
                    }
                }
                if (fbFunc->thunk() && fbFunc->thunked_function() != 0) {
                    thunkPairs.emplace_back(fbFunc->entry_point(), fbFunc->thunked_function());
                }
            }
            for (const auto& pair : thunkPairs) {
                auto* fm2 = program->getFunctionManager();
                Function* f = fm2->getFunctionAt(Address(ramSpace, static_cast<int64_t>(pair.first)));
                Function* target =
                    fm2->getFunctionAt(Address(ramSpace, static_cast<int64_t>(pair.second)));
                if (f && target) {
                    f->setThunk(true);
                    f->setThunkedFunction(target);
                }
            }
        }
    }

// -----------------------------------------------------------------------
    // References: memory / stack / register / external with type + source.
    // -----------------------------------------------------------------------
    if (auto* refs = snapshot->references()) {
        auto* rm = program->getReferenceManager();
        if (rm) {
            std::map<int64_t, std::unique_ptr<Register>> registerCache;
            for (auto* fbRef : *refs) {
                const RefType* type = refTypeByValue(static_cast<int8_t>(fbRef->ref_type_code()));
                if (!type) continue;
                Address from(ramSpace, static_cast<int64_t>(fbRef->from_address()));
                SourceType source = static_cast<SourceType>(fbRef->source());
                int opIndex = fbRef->op_index();
                Reference* ref = nullptr;
                uint8_t kind = fbRef->kind();
                if (kind == 1) {
                    ref = rm->addStackReference(from, opIndex, fbRef->stack_offset(), type, source);
                } else if (kind == 2) {
                    int64_t regOffset = static_cast<int64_t>(fbRef->to_address());
                    std::unique_ptr<Register>& reg = registerCache[regOffset];
                    if (!reg) {
                        char buf[32];
                        std::snprintf(buf, sizeof(buf), "r_0x%llx",
                                      static_cast<unsigned long long>(regOffset));
                        reg = std::make_unique<Register>(buf, "", Address(regSpace, regOffset), 8,
                                                         /*bigEndian=*/false, 0);
                    }
                    ref = rm->addRegisterReference(from, opIndex, reg.get(), type, source);
                } else if (kind == 3) {
                    std::string lib = fbRef->external_library() ? fbRef->external_library()->str() : "";
                    std::string label = fbRef->external_label() ? fbRef->external_label()->str() : "";
                    Address to(externalSpace, static_cast<int64_t>(fbRef->to_address()));
                    ref = rm->addExternalReference(from, lib, label, to, source, opIndex, type);
                } else {
                    Address to(ramSpace, static_cast<int64_t>(fbRef->to_address()));
                    ref = rm->addMemoryReference(from, to, type, source, opIndex);
                }
                if (ref && !fbRef->is_primary()) {
                    rm->setPrimary(ref, false);
                }
            }
        }
    }

    // Bookmarks
    if (auto* bkmks = snapshot->bookmarks()) {
        auto* bm = program->getBookmarkManager();
        if (bm) {
            for (auto* fbBk : *bkmks) {
                Address addr(ramSpace, static_cast<int64_t>(fbBk->address()));
                std::string text = fbBk->text() ? fbBk->text()->str() : "";
                std::string type = fbBk->type() ? fbBk->type()->str() : "";
                bm->setBookmark(addr, type, text);
            }
        }
    }

    // Equates (name/value + operand reference bindings; op_index < 0 = no
    // reference binding; same-named records refer to one shared equate)
    if (auto* eqs = snapshot->equates()) {
        auto* et = program->getEquateTable();
        if (et) {
            for (auto* fbEq : *eqs) {
                std::string name = fbEq->name() ? fbEq->name()->str() : "";
                if (name.empty()) continue;
                Equate* eq = et->getEquate(name);
                if (!eq) eq = et->createEquate(name, fbEq->value());
                if (eq && fbEq->op_index() >= 0) {
                    Address addr(ramSpace, static_cast<int64_t>(fbEq->address()));
                    et->addReference(eq, addr, fbEq->op_index());
                }
            }
        }
    }

    // Relocations (status/type/values/bytes/symbol preserved)
    if (auto* relocs = snapshot->relocations()) {
        auto* rti = dynamic_cast<RelocationTableImpl*>(program->getRelocationTable());
        if (rti) {
            for (auto* fbReloc : *relocs) {
                std::string typeStr = fbReloc->type() ? fbReloc->type()->str() : "";
                char* end = nullptr;
                long type = std::strtol(typeStr.c_str(), &end, 10);
                if (!typeStr.empty() && end && *end != '\0') type = 0;
                std::vector<int64_t> values;
                if (fbReloc->values()) {
                    for (auto v : *fbReloc->values()) values.push_back(v);
                }
                std::vector<uint8_t> bytes;
                if (fbReloc->bytes()) {
                    bytes.assign(fbReloc->bytes()->begin(), fbReloc->bytes()->end());
                }
                Address addr(ramSpace, static_cast<int64_t>(fbReloc->address()));
                rti->addRelocation(addr,
                                   static_cast<Relocation::Status>(fbReloc->status()),
                                   static_cast<int>(type), values, bytes,
                                   fbReloc->symbol_name() ? fbReloc->symbol_name()->str() : "");
            }
        }
    }

    // Function tags (definitions + tag-to-function assignments)
    if (auto* tags = snapshot->function_tags()) {
        auto* ftm = program->getFunctionTagManager();
        if (ftm) {
            for (auto* fbTag : *tags) {
                FunctionTag* tag = ftm->createFunctionTag(
                    fbTag->name() ? fbTag->name()->str() : "",
                    fbTag->comment() ? fbTag->comment()->str() : "");
                if (!tag || !fbTag->function_addresses()) continue;
                auto* fm = program->getFunctionManager();
                if (!fm) continue;
                for (auto addrVal : *fbTag->function_addresses()) {
                    Address addr(ramSpace, static_cast<int64_t>(addrVal));
                    Function* func = fm->getFunctionAt(addr);
                    if (func) func->addTagDirect(tag);
                }
            }
        }
    }

    // Register values (value LSB-first bytes restored from the stored
    // unsigned offset; mask preserved verbatim).
    if (auto* ctxRecords = snapshot->program_context()) {
        auto* ctxImpl = dynamic_cast<ProgramContextImpl*>(program->getProgramContext());
        if (ctxImpl) {
            const bool is64 = program->getLanguageID().getIdAsString().find("64") !=
                              std::string::npos;
            const int registerBytes = is64 ? 8 : 4;
            const std::map<std::string, int64_t> knownOffsets = {
                {"FS_OFFSET", 0x110},
                {"GS_OFFSET", 0x110},
            };
            for (auto* fbCtx : *ctxRecords) {
                std::string regName = fbCtx->register_name() ? fbCtx->register_name()->str() : "";
                if (regName.empty()) continue;
                auto known = knownOffsets.find(regName);
                int64_t regOffset = known != knownOffsets.end() ? known->second : 0;
                std::vector<uint8_t> mask;
                if (fbCtx->mask()) {
                    mask.assign(fbCtx->mask()->begin(), fbCtx->mask()->end());
                }
                // Register size follows the serialized mask (the context
                // register is 8 bytes even on 32-bit languages).
                const int regBytes = mask.empty()
                                         ? registerBytes
                                         : static_cast<int>(mask.size());
                if (static_cast<int>(mask.size()) > regBytes) {
                    mask.resize(static_cast<size_t>(regBytes));
                }
                Register* reg = ctxImpl->addOwnedRegister(std::make_unique<Register>(
                    regName, "", Address(regSpace, regOffset), regBytes,
                    /*bigEndian=*/false, 0));
                if (!reg) continue;
                if (mask.empty()) mask.assign(static_cast<size_t>(regBytes), 0xFF);
                uint64_t value = 0;
                if (fbCtx->value()) {
                    char* end = nullptr;
                    value = static_cast<uint64_t>(std::strtoull(fbCtx->value()->c_str(), &end, 10));
                }
                std::vector<uint8_t> valueBytes(mask.size(), 0);
                for (size_t i = 0; i < valueBytes.size(); ++i) {
                    valueBytes[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
                }
                Address start(ramSpace, static_cast<int64_t>(fbCtx->address()));
                Address end(ramSpace, static_cast<int64_t>(fbCtx->end_address()));
                RegisterValue rv(reg, valueBytes, mask);
                if (fbCtx->is_default()) {
                    ctxImpl->setDefaultValue(&rv, start, end);
                } else {
                    program->getProgramContext()->setRegisterValue(&rv, start, end);
                }
            }
        }
    }

    // Metadata
    if (auto* meta = snapshot->metadata()) {
        for (auto* fbMeta : *meta) {
            program->setMetadata(fbMeta->key() ? fbMeta->key()->str() : "",
                                 fbMeta->value() ? fbMeta->value()->str() : "");
        }
    }

    // Entry points (native symbol-table external entry points)
    if (auto* entries = snapshot->entry_points()) {
        if (auto* st = program->getSymbolTable()) {
            for (uint64_t ep : *entries) {
                st->addExternalEntryPoint(
                    Address(ramSpace, static_cast<int64_t>(ep)));
            }
        }
    }

    // Source maps: files are registered once per unique path, then entries.
    if (auto* srcMgr = program->getSourceFileManager()) {
        std::map<std::string, SourceFile*> filesByPath;
        if (auto* srcFiles = snapshot->source_files()) {
            for (auto* fbPath : *srcFiles) {
                std::string path = fbPath ? fbPath->str() : "";
                if (path.empty()) continue;
                SourceFile*& file = filesByPath[path];
                if (!file) {
                    file = srcMgr->addSourceFile(path, "");
                }
            }
        }
        if (auto* smEntries = snapshot->source_map_entries()) {
            for (auto* fbEntry : *smEntries) {
                std::string path =
                    fbEntry->source_file_path() ? fbEntry->source_file_path()->str() : "";
                if (path.empty() || fbEntry->line_number() <= 0) continue;
                SourceFile*& file = filesByPath[path];
                if (!file) {
                    file = srcMgr->addSourceFile(path, "");
                }
                if (!file) continue;
                Address base(ramSpace, static_cast<int64_t>(fbEntry->address()));
                try {
                    srcMgr->addSourceMapEntry(file, fbEntry->line_number(), base,
                                              fbEntry->length());
                } catch (const std::exception&) {
                    // Overflowing/corrupt entry: skip.
                }
            }
        }
    }

    // Module tree: modules, fragments, relationships, fragment ranges.
    if (auto* treeMgr = program->getTreeManager()) {
        if (auto* trees = snapshot->trees()) {
            for (auto* fbTree : *trees) {
                std::string treeName = fbTree->name() ? fbTree->name()->str() : "";
                if (treeName.empty()) continue;
                if (treeMgr->getModules().find(treeName) == treeMgr->getModules().end()) {
                    treeMgr->createRootModule(treeName);
                }
                auto& mods = treeMgr->getModulesMutable();
                auto it = mods.find(treeName);
                if (it == mods.end()) continue;
                ModuleManager* mm = it->second.get();
                if (auto* modules = snapshot->tree_modules()) {
                    for (auto* fbMod : *modules) {
                        if (fbMod->tree_name() && fbMod->tree_name()->str() != treeName) continue;
                        mm->loadModule(fbMod->id(), fbMod->name() ? fbMod->name()->str() : "",
                                       fbMod->comment() ? fbMod->comment()->str() : "");
                    }
                }
                if (auto* fragments = snapshot->tree_fragments()) {
                    for (auto* fbFrag : *fragments) {
                        if (fbFrag->tree_name() && fbFrag->tree_name()->str() != treeName) continue;
                        mm->loadFragment(fbFrag->id(), fbFrag->name() ? fbFrag->name()->str() : "",
                                         fbFrag->comment() ? fbFrag->comment()->str() : "");
                    }
                }
                if (auto* rels = snapshot->tree_relationships()) {
                    for (auto* fbRel : *rels) {
                        if (fbRel->tree_name() && fbRel->tree_name()->str() != treeName) continue;
                        mm->addRelationship(fbRel->parent_id(), fbRel->child_id(),
                                            fbRel->child_index());
                    }
                }
                if (auto* ranges = snapshot->tree_fragment_ranges()) {
                    for (auto* fbRange : *ranges) {
                        if (fbRange->tree_name() && fbRange->tree_name()->str() != treeName) continue;
                        const auto& frags = mm->getFragments();
                        auto fit = frags.find(fbRange->fragment_id());
                        if (fit == frags.end() || !fit->second) continue;
                        fit->second->addRange(
                            Address(ramSpace, static_cast<int64_t>(fbRange->start())),
                            Address(ramSpace, static_cast<int64_t>(fbRange->end())));
                    }
                }
            }
        }
    }

    return program;
}

std::unique_ptr<ProgramDB> SnapshotReader::loadFromFile(const std::string& path) {
    auto data = readFile(path);
    return deserialize(data.data(), data.size());
}

} // namespace storage
} // namespace ghidra