#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/EquateTable.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/Relocation.h>
#include <ghidra/FunctionTagManager.h>
#include <ghidra/FunctionTag.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/Composite.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include "program_generated.h"
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <vector>
#include <memory>
#include <stdexcept>
#include <algorithm>

namespace ghidra {
namespace storage {

namespace fb = fbschema;

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

    // Set basic metadata
    if (!binaryName.empty())
        program->setName(binaryName);
    if (snapshot->language_id())
        program->setLanguageID(LanguageID(snapshot->language_id()->str()));
    if (snapshot->compiler_spec_id())
        program->setCompilerSpecID(CompilerSpecID(snapshot->compiler_spec_id()->str()));

    // Register address spaces on the program's address factory
    AddressSpace* ramSpace = nullptr;
    {
        auto* af = dynamic_cast<ProgramAddressFactory*>(program->getAddressFactory());
        if (af) {
            ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 1);
            auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2);
            auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3);
            auto* regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 4);
            auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 5);
            af->addAddressSpace(ramSpace);
            af->addAddressSpace(constSpace);
            af->addAddressSpace(uniqueSpace);
            af->addAddressSpace(regSpace);
            af->addAddressSpace(stackSpace);
            af->setDefaultSpace(ramSpace);
        }
    }

    bool bigEndian = snapshot->is_big_endian();

    // Build address space and memory if blocks present
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
                if (block && fbBlock->permissions()) {
                    const char* perm = fbBlock->permissions()->c_str();
                    bool r = perm[0] != '\0' && perm[0] != '-';
                    bool w = perm[1] != '\0' && perm[1] != '-';
                    bool x = perm[2] != '\0' && perm[2] != '-';
                    block->setPermissions(r, w, x);
                }
            }
            program->setMemory(defaultMem.release());
        }
    }

    // Set address metadata
    if (snapshot->image_base() != 0)
        program->setImageBase(Address(ramSpace, static_cast<int64_t>(snapshot->image_base())));
    if (snapshot->min_address() != 0 || snapshot->max_address() != 0) {
        program->setMinAddress(Address(ramSpace, static_cast<int64_t>(snapshot->min_address())));
        program->setMaxAddress(Address(ramSpace, static_cast<int64_t>(snapshot->max_address())));
    }

    // Type ID map — built during data type restoration, used by function restoration
    std::map<uint64_t, DataType*> idMap;

    // Restore data types — two-pass with stable IDs
    if (auto* dataTypes = snapshot->data_types()) {
        auto* dtm = program->getDataTypeManager();
        auto* dtmImpl = dynamic_cast<DataTypeManagerImpl*>(dtm);
        if (dtmImpl) {
            // Collect all snapshot entries + build idMap for built-ins
            struct TypeEntry { DataType* dt; std::string kind; const fb::DataTypeRecord* fbDt; };
            std::vector<TypeEntry> pending;

            // Pre-populate idMap with built-in types from the fresh DTM
            for (auto* dt : dtm->getDataTypes()) {
                long id = dtmImpl->getDataTypeId(dt);
                if (id > 0) idMap[static_cast<uint64_t>(id)] = dt;
            }

            // Pass 1: create struct/union/enum shells + builtins (types with no constructor deps)
            for (auto* fbDt : *dataTypes) {
                std::string name = fbDt->name() ? fbDt->name()->str() : "";
                std::string typeKind = fbDt->type_kind() ? fbDt->type_kind()->str() : "";
                int size = fbDt->size();
                uint64_t dtId = fbDt->dt_id();
                if (name.empty() || dtId == 0) continue;
                if (dtmImpl->getDataType(CategoryPath::ROOT(), name)) continue;

                DataType* newDt = nullptr;
                bool deferred = false;
                if (typeKind == "struct") {
                    newDt = new StructureDataType(CategoryPath::ROOT(), name, 0, dtmImpl);
                } else if (typeKind == "union") {
                    newDt = new UnionDataType(CategoryPath::ROOT(), name, dtmImpl);
                } else if (typeKind == "enum") {
                    newDt = new EnumDataType(CategoryPath::ROOT(), name, size, dtmImpl);
                } else if (name == "dword") {
                    newDt = new DWordDataType(dtmImpl);
                } else if (name == "qword") {
                    newDt = new QWordDataType(dtmImpl);
                } else if (name == "word") {
                    newDt = new WordDataType(dtmImpl);
                } else if (name == "bool") {
                    newDt = new BooleanDataType(dtmImpl);
                } else {
                    deferred = true; // pointer/array/typedef — need deps
                }
                if (newDt) {
                    dtmImpl->addDataTypeWithId(newDt, static_cast<long>(dtId));
                    idMap[dtId] = newDt;
                    TypeEntry e;
                    e.dt = newDt; e.kind = typeKind; e.fbDt = fbDt;
                    pending.push_back(e); // track for pass 2+3
                } else if (deferred) {
                    TypeEntry e;
                    e.dt = nullptr; e.kind = typeKind; e.fbDt = fbDt;
                    pending.push_back(e); // defer creation to pass 2
                }
            }

            // Pass 2: iterative dependency resolution for pointer/array/typedef
            bool progress = true;
            while (progress) {
                progress = false;
                for (auto& entry : pending) {
                    if (entry.dt) continue; // already created
                    uint64_t dtId = entry.fbDt->dt_id();
                    DataType* dep = nullptr;
                    std::string kind = entry.kind;
                    if (kind == "pointer") {
                        uint64_t targetId = entry.fbDt->pointer_target_id();
                        auto it = targetId > 0 ? idMap.find(targetId) : idMap.end();
                        dep = (it != idMap.end()) ? it->second : nullptr;
                        if (dep) {
                            int ptrSize = entry.fbDt->size();
                            entry.dt = new PointerDataType(dep, ptrSize > 0 ? ptrSize : 8, dtmImpl);
                        }
                    } else if (kind == "array") {
                        uint64_t elemId = entry.fbDt->array_element_id();
                        auto it = elemId > 0 ? idMap.find(elemId) : idMap.end();
                        dep = (it != idMap.end()) ? it->second : nullptr;
                        if (dep) {
                            int count = entry.fbDt->array_element_count();
                            entry.dt = new ArrayDataType(dep, count > 0 ? count : 1, -1, dtmImpl);
                        }
                    } else if (kind == "typedef") {
                        uint64_t baseId = entry.fbDt->typedef_base_id();
                        auto it = baseId > 0 ? idMap.find(baseId) : idMap.end();
                        dep = (it != idMap.end()) ? it->second : nullptr;
                        if (dep) {
                            std::string name = entry.fbDt->name()->str();
                            entry.dt = new TypedefDataType(CategoryPath::ROOT(), name, dep, dtmImpl);
                        }
                    }
                    if (entry.dt) {
                        dtmImpl->addDataTypeWithId(entry.dt, static_cast<long>(dtId));
                        idMap[dtId] = entry.dt;
                        progress = true;
                    }
                }
            }

            // Pass 3: fill struct/union fields and enum values
            for (auto& entry : pending) {
                if (!entry.dt) continue;
                if (entry.kind == "struct") {
                    if (auto* fields = entry.fbDt->fields()) {
                        auto* st = dynamic_cast<StructureDataType*>(entry.dt);
                        if (st) {
                            for (auto* field : *fields) {
                                std::string fn = field->name() ? field->name()->str() : "";
                                uint64_t ftId = field->data_type_id();
                                auto fit = ftId > 0 ? idMap.find(ftId) : idMap.end();
                                DataType* ft = (fit != idMap.end()) ? fit->second : nullptr;
                                if (ft) st->add(ft, fn, "");
                            }
                        }
                    }
                } else if (entry.kind == "union") {
                    if (auto* fields = entry.fbDt->fields()) {
                        auto* un = dynamic_cast<UnionDataType*>(entry.dt);
                        if (un) {
                            for (auto* field : *fields) {
                                std::string fn = field->name() ? field->name()->str() : "";
                                uint64_t ftId = field->data_type_id();
                                auto fit = ftId > 0 ? idMap.find(ftId) : idMap.end();
                                DataType* ft = (fit != idMap.end()) ? fit->second : nullptr;
                                if (ft) un->add(ft, fn, "");
                            }
                        }
                    }
                } else if (entry.kind == "enum") {
                    if (auto* evs = entry.fbDt->enum_values()) {
                        auto* en = dynamic_cast<EnumDataType*>(entry.dt);
                        if (en) {
                            for (auto* ev : *evs) {
                                en->add(ev->name() ? ev->name()->str() : "", ev->value());
                            }
                        }
                    }
                }
            }
        }
    }

    // Restore functions
    if (auto* funcs = snapshot->functions()) {
        auto* fm = program->getFunctionManager();
        if (fm) {
            for (auto* fbFunc : *funcs) {
                std::string name = fbFunc->name() ? fbFunc->name()->str() : "";
                Address entry(ramSpace, static_cast<int64_t>(fbFunc->entry_point()));
                AddressSet body;
                if (auto* ranges = fbFunc->body_ranges()) {
                    for (auto* range : *ranges) {
                        Address start(ramSpace, static_cast<int64_t>(range->offset()));
                        body.addRange(start, start.add(static_cast<int64_t>(range->length()) - 1));
                    }
                }
                Function* func = fm->createFunction(name, entry, body, SourceType::DEFAULT);
                if (func) {
                    if (fbFunc->has_no_return())
                        func->setHasNoReturn(true);
                    if (fbFunc->is_inline())
                        func->setInline(true);
                    if (fbFunc->call_fixup())
                        func->setCallFixup(fbFunc->call_fixup()->str());
                    func->setSignatureSource(static_cast<SignatureSource>(fbFunc->signature_source()));

                    // Restore calling convention
                    if (fbFunc->calling_convention()) {
                        PrototypeModel* cc = fm->getCallingConvention(fbFunc->calling_convention()->str());
                        if (cc) func->setCallingConvention(cc);
                    }

                    // Restore return type (prefer ID, fall back to name)
                    if (fbFunc->return_type_id() > 0) {
                        auto typeIt = idMap.find(fbFunc->return_type_id());
                        if (typeIt != idMap.end()) func->setReturnType(typeIt->second);
                    } else if (fbFunc->return_type()) {
                        DataTypeManager* dtm = program->getDataTypeManager();
                        if (dtm) {
                            DataType* retDt = dtm->getDataType(CategoryPath::ROOT(), fbFunc->return_type()->str());
                            if (retDt) func->setReturnType(retDt);
                        }
                    }

                    // Restore parameters (prefer ID, fall back to name)
                    if (auto* fbParams = fbFunc->params()) {
                        for (auto* fbParam : *fbParams) {
                            std::string pname = fbParam->name() ? fbParam->name()->str() : "";
                            DataType* dt = nullptr;
                            if (fbParam->data_type_id() > 0) {
                                auto typeIt = idMap.find(fbParam->data_type_id());
                                if (typeIt != idMap.end()) dt = typeIt->second;
                            } else if (fbParam->data_type_name()) {
                                DataTypeManager* dtm = program->getDataTypeManager();
                                if (dtm) dt = dtm->getDataType(CategoryPath::ROOT(), fbParam->data_type_name()->str());
                            }
                            if (dt) {
                                ghidra::VariableStorage vs;
                                auto* param = new ParameterImpl(pname, dt, vs, program.get());
                                func->addParameter(param);
                            }
                        }
                    }
                }
            }
        }
    }

    // Restore symbols
    if (auto* syms = snapshot->symbols()) {
        auto* st = program->getSymbolTable();
        if (st) {
            for (auto* fbSym : *syms) {
                std::string name = fbSym->name() ? fbSym->name()->str() : "";
                Address addr(ramSpace, static_cast<int64_t>(fbSym->address()));
                st->createLabel(addr, name, SourceType::DEFAULT);
            }
        }
    }

    // Restore bookmarks
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

    // Restore equates
    if (auto* eqs = snapshot->equates()) {
        auto* et = program->getEquateTable();
        if (et) {
            for (auto* fbEq : *eqs) {
                std::string name = fbEq->name() ? fbEq->name()->str() : "";
                et->createEquate(name, fbEq->value());
            }
        }
    }

    // Restore external locations
    if (auto* extLocs = snapshot->external_locations()) {
        auto* em = program->getExternalManager();
        if (em) {
            for (auto* fbLoc : *extLocs) {
                std::string libName = fbLoc->library_name() ? fbLoc->library_name()->str() : "";
                std::string label = fbLoc->name() ? fbLoc->name()->str() : "";
                Address addr(ramSpace, static_cast<int64_t>(fbLoc->address()));
                em->addExternalLocation(libName, label, addr);
            }
        }
    }

    // Relocations — read from snapshot but RelocationTable has no add API, skip restore

    return program;
}

std::unique_ptr<ProgramDB> SnapshotReader::loadFromFile(const std::string& path) {
    auto data = readFile(path);
    return deserialize(data.data(), data.size());
}

} // namespace storage
} // namespace ghidra
