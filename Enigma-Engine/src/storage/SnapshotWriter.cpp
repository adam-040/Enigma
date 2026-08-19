#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/storage/Repository.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/Parameter.h>
#include <ghidra/LocalVariable.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Register.h>
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
#include <ghidra/SourceFileManager.h>
#include <ghidra/SourceFileManagerImpl.h>
#include <ghidra/FunctionTagManager.h>
#include <ghidra/FunctionTag.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataOrganizationImpl.h>
#include <ghidra/DataType.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/Composite.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/Array.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/ParameterDefinition.h>
#include <ghidra/BitFieldDataType.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/TreeManager.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/ModuleDB.h>
#include <ghidra/FragmentDB.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include "program_generated.h"
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <ctime>
#include <functional>
#include <vector>
#include <algorithm>
#include <map>
#include <limits>
#include <cstdint>

namespace ghidra {
namespace storage {

namespace fb = fbschema;

// Variable storage in a compact, parser-independent form:
// "u" | "reg:<offset>:<size>" | "stack:<signedOffset>:<size>" |
// "mem:<offset>:<size>".  Deterministic on both sides of the round trip.
std::string storageToString(const VariableStorage& s) {
    if (s.isUnassignedStorage() || s.isVoidStorage() || s.isBadStorage() ||
        !s.isValid()) {
        return "u";
    }
    if (s.isRegisterStorage()) {
        Register* reg = s.getRegister();
        if (!reg) return "u";
        return "reg:" + std::to_string(reg->getAddress().getOffset()) + ":" +
               std::to_string(s.size());
    }
    if (s.hasStackStorage()) {
        return "stack:" + std::to_string(static_cast<int64_t>(s.getStackOffset())) + ":" +
               std::to_string(s.size());
    }
    if (s.isMemoryStorage() && s.getMinAddress().isValid()) {
        return "mem:" + std::to_string(s.getMinAddress().getOffset()) + ":" +
               std::to_string(s.size());
    }
    return "u";
}

uint64_t SnapshotWriter::addressToU64(const Address& addr) {
    return static_cast<uint64_t>(addr.getOffset());
}

std::vector<uint8_t> SnapshotWriter::serialize(const ProgramDB& program) {
    flatbuffers::FlatBufferBuilder builder(1024 * 1024);

    std::string langId = program.getLanguageID().toString();
    std::string compId = program.getCompilerSpecID().toString();
    uint64_t imageBase = 0, minAddr = 0, maxAddr = 0;
    bool bigEndian = false;
    imageBase = static_cast<uint64_t>(program.getImageBase().getOffset());
    minAddr = static_cast<uint64_t>(program.getMinAddress().getOffset());
    maxAddr = static_cast<uint64_t>(program.getMaxAddress().getOffset());
    if (auto* mem = program.getMemory()) {
        bigEndian = mem->isBigEndian();
    }
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));

    auto* dtm = program.getDataTypeManager();
    auto* listing = program.getListing();

    // Stable snapshot id space for data types: the DTM's getDataTypeId is not
    // stable across managers (corpus ids overlap the fresh builtin ids 1..16
    // and addDataTypeWithId clobbers colliding entries), so every datatype is
    // remapped to a fresh id starting above the builtin range.  The map is
    // keyed by pointer because two types can claim the same DTM id.
    std::map<const DataType*, uint64_t> dtToSnapId;
    uint64_t nextSnapId = 1000;
    if (dtm) {
        for (auto* dt : dtm->getDataTypes()) {
            if (!dt || dt->getName().empty()) continue;
            dtToSnapId[dt] = nextSnapId++;
        }
    }
    auto snapIdOf = [&dtToSnapId](const DataType* dt) -> uint64_t {
        if (!dt) return 0;
        auto it = dtToSnapId.find(dt);
        return it != dtToSnapId.end() ? it->second : 0;
    };

    // Unregistered (implicit) types — e.g. an implicit pointer attached to a
    // data unit or struct field, or a pointer-to-pointer Ghidra auto-created —
    // still need a snapshot id.  Materialize them as inline records (emitted
    // after every registered type so the reader can dedup them against any
    // registered type that claims the same path).
    std::vector<flatbuffers::Offset<fb::DataTypeRecord>> materializedTypes;
    std::function<uint64_t(DataType*)> materializeInline;
    materializeInline = [&](DataType* d) -> uint64_t {
        if (!d) return 0;
        auto it = dtToSnapId.find(d);
        if (it != dtToSnapId.end()) return it->second;
        uint64_t id = nextSnapId++;
        dtToSnapId[d] = id;
        if (auto* def = dynamic_cast<DefaultDataType*>(d)) {
            // Ghidra DataType.DEFAULT (id 0, "undefined"): a global singleton
            // that is never registered in the DTM, so it cannot be in the
            // registered-type phase.  Serialize it by name; the reader
            // rebuilds a per-manager instance.
            materializedTypes.push_back(fb::CreateDataTypeRecordDirect(builder,
                id,
                "undefined",
                nullptr,
                def->getLength(),
                "builtin",
                nullptr,
                nullptr,
                nullptr,
                0, 0, 0, 0, -1, 0,
                /*inline_materialized=*/true,
                /*funcdef_varargs=*/false));
        } else if (auto* ptr = dynamic_cast<Pointer*>(d)) {
            std::string catPath = ptr->getCategoryPath().getPath();
            std::string desc = ptr->getDescription();
            // Implicit pointers (language-default length) serialize as -1 so
            // the reader rebuilds the suffix-less name instead of resolving
            // getLength() to the default pointer size and creating "*64".
            int ptrLen = ptr->hasLanguageDependantLength() ? -1 : ptr->getLength();
            materializedTypes.push_back(fb::CreateDataTypeRecordDirect(builder,
                id,
                ptr->getName().c_str(),
                catPath.empty() ? nullptr : catPath.c_str(),
                ptrLen,
                "pointer",
                desc.empty() ? nullptr : desc.c_str(),
                nullptr,
                nullptr,
                materializeInline(ptr->getDataType()),
                0, 0, 0, -1, 0, /*inline_materialized=*/true,
                /*funcdef_varargs=*/false));
        } else if (auto* arr = dynamic_cast<Array*>(d)) {
            std::string catPath = arr->getCategoryPath().getPath();
            std::string desc = arr->getDescription();
            uint64_t elemId = materializeInline(arr->getDataType());
            materializedTypes.push_back(fb::CreateDataTypeRecordDirect(builder,
                id,
                arr->getName().c_str(),
                catPath.empty() ? nullptr : catPath.c_str(),
                arr->getLength(),
                "array",
                desc.empty() ? nullptr : desc.c_str(),
                nullptr,
                nullptr,
                0, elemId, arr->getNumElements(), 0, -1, 0,
                /*inline_materialized=*/true,
                /*funcdef_varargs=*/false));
        }
        return id;
    };
    // Snap id for a referenced type, materializing it inline if it is an
    // unregistered helper so the id always resolves on the read side.
    auto resolveSnapId = [&](const DataType* dt) -> uint64_t {
        uint64_t id = snapIdOf(dt);
        return id != 0 ? id : materializeInline(const_cast<DataType*>(dt));
    };

    // Memory blocks
    std::vector<flatbuffers::Offset<fb::MemoryBlock>> memBlocks;
    if (auto* mem = program.getMemory()) {
        for (auto* block : mem->getBlocks()) {
            std::vector<uint8_t> blockBytes;
            if (block && block->isInitialized() && block->getSize() > 0 &&
                block->getSize() <= static_cast<long long>(std::numeric_limits<int>::max())) {
                blockBytes.resize(static_cast<size_t>(block->getSize()));
                int nread = block->getBytes(block->getStart(), blockBytes.data(),
                                            static_cast<int>(blockBytes.size()));
                if (nread < static_cast<int>(blockBytes.size())) {
                    blockBytes.resize(static_cast<size_t>(std::max(0, nread)));
                }
            }
            char perm[4] = {
                block->isRead() ? 'r' : '-',
                block->isWrite() ? 'w' : '-',
                block->isExecute() ? 'x' : '-',
                '\0'
            };
            memBlocks.push_back(fb::CreateMemoryBlockDirect(builder,
                block->getName().c_str(),
                block->getComment().c_str(),
                static_cast<uint64_t>(block->getStart().getOffset()),
                static_cast<uint64_t>(block->getSize()),
                perm,
                "default",
                blockBytes.empty() ? nullptr : &blockBytes));
        }
    }

    // Code units: instructions and data units (Listing is the source of
    // truth; the listing is what the user sees and edits).
    std::vector<flatbuffers::Offset<fb::CodeUnit>> codeUnits;
    std::vector<flatbuffers::Offset<fb::CommentRecord>> comments;
    auto emitComment = [&](const Address& addr, const char* slot,
                           const std::string& text) {
        if (text.empty()) return;
        comments.push_back(fb::CreateCommentRecordDirect(builder,
            static_cast<uint64_t>(addr.getOffset()), slot, text.c_str()));
    };
    if (listing) {
        for (auto* inst : listing->getAllInstructions()) {
            if (!inst) continue;
            codeUnits.push_back(fb::CreateCodeUnitDirect(builder,
                static_cast<uint64_t>(inst->getAddress().getOffset()),
                static_cast<uint16_t>(inst->getLength()),
                "instruction",
                inst->getDataType() ? inst->getDataType()->getName().c_str() : nullptr,
                nullptr,
                inst->getMnemonicString().c_str(),
                0,
                0));
            emitComment(inst->getAddress(), "EOL", inst->getComment());
            emitComment(inst->getAddress(), "PRE", inst->getPreComment());
            emitComment(inst->getAddress(), "POST", inst->getPostComment());
            emitComment(inst->getAddress(), "PLATE", inst->getPlateComment());
            emitComment(inst->getAddress(), "REPEATABLE", inst->getRepeatableComment());
        }
        for (auto* data : listing->getAllData()) {
            if (!data) continue;
            codeUnits.push_back(fb::CreateCodeUnitDirect(builder,
                static_cast<uint64_t>(data->getAddress().getOffset()),
                static_cast<uint16_t>(data->getLength()),
                "data",
                data->getDataType() ? data->getDataType()->getName().c_str() : nullptr,
                nullptr,
                nullptr,
                resolveSnapId(data->getDataType()),
                data->getLength()));
            emitComment(data->getAddress(), "EOL", data->getComment());
            emitComment(data->getAddress(), "PRE", data->getPreComment());
            emitComment(data->getAddress(), "POST", data->getPostComment());
            emitComment(data->getAddress(), "PLATE", data->getPlateComment());
            emitComment(data->getAddress(), "REPEATABLE", data->getRepeatableComment());
        }
    }

    // Functions
    std::vector<flatbuffers::Offset<fb::FunctionRecord>> functions;
    std::vector<flatbuffers::Offset<fb::CallingConventionRecord>> conventions;
    if (auto* fm = program.getFunctionManager()) {
        for (const std::string& ccName : fm->getCallingConventionNames()) {
            if (ccName.empty()) continue;
            conventions.push_back(fb::CreateCallingConventionRecordDirect(builder,
                ccName.c_str()));
        }
        auto it = fm->getFunctions(true);
        while (it.hasNext()) {
            Function* func = it.next();
            std::vector<flatbuffers::Offset<fb::AddressRange>> bodyRanges;
            for (auto& range : func->getBody().toList()) {
                bodyRanges.push_back(fb::CreateAddressRangeDirect(builder, "ram",
                    static_cast<uint64_t>(range.getMinAddress().getOffset()),
                    static_cast<uint64_t>(range.getLength())));
            }
            std::vector<flatbuffers::Offset<fb::ParamRecord>> params;
            for (auto* param : func->getParameters()) {
                if (!param) continue;
                DataType* paramDt = param->getDataType();
                int ordinal = -1;
                if (auto* p = dynamic_cast<Parameter*>(param)) {
                    ordinal = p->getOrdinal();
                }
                params.push_back(fb::CreateParamRecordDirect(builder,
                    param->getName().c_str(),
                    paramDt ? paramDt->getName().c_str() : nullptr,
                    resolveSnapId(paramDt),
                    ordinal,
                    storageToString(param->getVariableStorage()).c_str()));
            }
            std::vector<flatbuffers::Offset<fb::LocalVarRecord>> locals;
            for (auto* var : func->getLocalVariables()) {
                if (!var) continue;
                DataType* varDt = var->getDataType();
                int firstUse = 0;
                if (auto* lv = dynamic_cast<LocalVariable*>(var)) {
                    firstUse = lv->getFirstUseOffset();
                }
                locals.push_back(fb::CreateLocalVarRecordDirect(builder,
                    var->getName().c_str(),
                    resolveSnapId(varDt),
                    firstUse,
                    storageToString(var->getVariableStorage()).c_str()));
            }
            DataType* retDt = func->getReturnType();
            Function* thunked = func->getThunkedFunction();
            functions.push_back(fb::CreateFunctionRecordDirect(builder,
                func->getName().c_str(),
                static_cast<uint64_t>(func->getEntryPoint().getOffset()),
                bodyRanges.empty() ? nullptr : &bodyRanges,
                func->getCallingConvention() ? func->getCallingConvention()->getName().c_str() : nullptr,
                retDt ? retDt->getName().c_str() : nullptr,
                resolveSnapId(retDt),
                static_cast<uint64_t>(func->getStackFrameSize()),
                func->isExternal(),
                func->hasNoReturn(),
                func->isInline(),
                func->getCallFixup().empty() ? nullptr : func->getCallFixup().c_str(),
                static_cast<uint8_t>(func->getSignatureSource()),
                nullptr,
                params.empty() ? nullptr : &params,
                func->isThunk(),
                thunked ? static_cast<uint64_t>(thunked->getEntryPoint().getOffset()) : 0,
                locals.empty() ? nullptr : &locals));
        }
    }

    // Symbols: full path of the parent namespace so nested namespaces
    // survive the round trip.
    auto nsPath = [](const Namespace* ns) -> std::string {
        std::string path;
        while (ns && !ns->isGlobal()) {
            const std::string name = ns->getName();
            path = path.empty() ? name : name + "::" + path;
            ns = ns->getParent();
        }
        return path;
    };
    std::vector<flatbuffers::Offset<fb::SymbolRecord>> symbols;
    if (auto* st = program.getSymbolTable()) {
        auto it = st->getAllProgramSymbols(true);
        while (it.hasNext()) {
            Symbol* sym = it.next();
            std::string ns = sym->getParentNamespace() ? nsPath(sym->getParentNamespace()) : "";
            uint64_t address = static_cast<uint64_t>(sym->getAddress().getOffset());
            const AddressSpace* space = sym->getAddress().getAddressSpace();
            if (space && space->getType() == AddressSpace::TYPE_EXTERNAL) {
                // External symbols carry the full 0x5000000000000000|offset
                // address-map key (mirrors the importer's external space).
                address = 0x5000000000000000ull | (address & 0xFFFFFFFFull);
            }
            symbols.push_back(fb::CreateSymbolRecordDirect(builder,
                sym->getName().c_str(),
                ns.empty() ? nullptr : ns.c_str(),
                address,
                symbolTypeToString(sym->getSymbolType()).c_str(),
                sym->isPrimary(),
                static_cast<int>(sym->getSource())));
        }
    }

    // References
    std::vector<flatbuffers::Offset<fb::ReferenceRecord>> references;
    if (auto* rm = program.getReferenceManager()) {
        for (auto* ref : rm->getAllReferences()) {
            if (!ref) continue;
            const Address& to = ref->getToAddress();
            uint8_t kind = 0;  // memory
            int stackOffset = 0;
            std::string toSpace;
            std::string extLib;
            std::string extLabel;
            if (ref->isStackReference()) {
                kind = 1;
                if (const auto* sr = dynamic_cast<const StackReference*>(ref)) {
                    stackOffset = sr->getStackOffset();
                }
            } else if (ref->isExternalReference()) {
                kind = 3;
                toSpace = to.getAddressSpace() ? to.getAddressSpace()->getName() : "";
                if (auto* em = program.getExternalManager()) {
                    if (ExternalLocation* loc = em->getExternalLocation(to)) {
                        extLib = loc->getLibraryName();
                        extLabel = loc->getLabel();
                    }
                }
            } else if (to.getAddressSpace() &&
                       to.getAddressSpace()->getType() == AddressSpace::TYPE_REGISTER) {
                kind = 2;
                toSpace = "register";
            }
            references.push_back(fb::CreateReferenceRecordDirect(builder,
                static_cast<uint64_t>(ref->getFromAddress().getOffset()),
                static_cast<uint64_t>(to.getOffset()),
                nullptr,
                ref->isPrimary(),
                ref->getOperandIndex(),
                ref->getReferenceType() ? ref->getReferenceType()->getValue() : 0,
                static_cast<uint8_t>(ref->getSource()),
                kind,
                toSpace.empty() ? nullptr : toSpace.c_str(),
                stackOffset,
                extLib.empty() ? nullptr : extLib.c_str(),
                extLabel.empty() ? nullptr : extLabel.c_str()));
        }
    }

    // Data types — full recursive serialization
    std::vector<flatbuffers::Offset<fb::DataTypeRecord>> dataTypes;
    if (dtm) {
        for (auto* dt : dtm->getDataTypes()) {
            std::string catPath = dt->getCategoryPath().getPath();
            std::string desc = dt->getDescription();
            std::string dtName = dt->getName();
            if (dtName.empty()) continue;

            std::string typeKind;
            if (dynamic_cast<const Structure*>(dt)) typeKind = "struct";
            else if (dynamic_cast<const Union*>(dt)) typeKind = "union";
            else if (dynamic_cast<const Enum*>(dt)) typeKind = "enum";
            else if (dynamic_cast<const Pointer*>(dt)) typeKind = "pointer";
            else if (dynamic_cast<const Array*>(dt)) typeKind = "array";
            else if (dynamic_cast<const TypeDef*>(dt)) typeKind = "typedef";
            else if (dynamic_cast<const FunctionDefinitionDataType*>(dt)) typeKind = "function";
            else typeKind = "builtin";

            std::vector<flatbuffers::Offset<fb::StructField>> fields;
            std::vector<flatbuffers::Offset<fb::EnumValue>> enumValues;
            uint64_t pointerTargetId = 0;
            uint64_t arrayElementId = 0;
            int arrayElementCount = 0;
            uint64_t typedefBaseId = 0;
            int pack = -1;
            int minAlignment = 0;
            bool funcdefVarArgs = false;

            if (auto* comp = dynamic_cast<const Composite*>(dt)) {
                int nc = comp->getNumComponents();
                for (int i = 0; i < nc; ++i) {
                    DataTypeComponent* dc = comp->getComponent(i);
                    if (!dc) continue;
                    std::string fieldName = dc->getFieldName();
                    int offset = dc->getOffset();
                    DataType* fieldDt = dc->getDataType();
                    int bitOffset = -1, bitSize = -1;
                    long bitBaseId = 0;
                    if (dc->isBitFieldComponent()) {
                        if (auto* bf = dynamic_cast<BitFieldDataType*>(fieldDt)) {
                            bitOffset = bf->getBitOffset();
                            bitSize = bf->getBitSize();
                            bitBaseId = static_cast<long>(snapIdOf(bf->getBaseDataType()));
                        }
                    }
                    fields.push_back(fb::CreateStructField(builder,
                        builder.CreateString(fieldName), offset, resolveSnapId(fieldDt),
                        dc->getLength(), builder.CreateString(dc->getComment()),
                        bitOffset, bitSize, static_cast<uint64_t>(bitBaseId),
                        bitSize >= 0 ? dc->getLength() : 0));
                }
                pack = comp->getExplicitPackingValue();
                minAlignment = comp->getExplicitMinimumAlignment();
            } else if (auto* fd = dynamic_cast<const FunctionDefinition*>(dt)) {
                // Function-definition parameters ride in the fields vector
                // (offset = ordinal) and the return type in pointer_target_id.
                std::vector<ParameterDefinition*> args = fd->getArguments();
                for (auto* arg : args) {
                    if (!arg) continue;
                    DataType* argDt = arg->getDataType();
                    fields.push_back(fb::CreateStructField(builder,
                        builder.CreateString(arg->getName()), arg->getOrdinal(),
                        resolveSnapId(argDt), 0,
                        builder.CreateString(arg->getComment()),
                        -1, -1, 0, 0));
                }
                pointerTargetId = resolveSnapId(fd->getReturnType());
                funcdefVarArgs = fd->hasVarArgs();
            }

            if (auto* en = dynamic_cast<const Enum*>(dt)) {
                auto names = en->getNames();
                auto values = en->getValues();
                size_t n = std::min(names.size(), values.size());
                for (size_t i = 0; i < n; ++i) {
                    auto evName = builder.CreateString(names[i]);
                    std::string comment = en->getComment(names[i]);
                    enumValues.push_back(fb::CreateEnumValue(
                        builder, evName, values[i],
                        comment.empty() ? 0 : builder.CreateString(comment)));
                }
            }

            if (auto* ptr = dynamic_cast<const Pointer*>(dt)) {
                DataType* target = ptr->getDataType();
                pointerTargetId = resolveSnapId(target);
            }

            if (auto* arr = dynamic_cast<const Array*>(dt)) {
                DataType* elem = arr->getDataType();
                arrayElementId = resolveSnapId(elem);
                arrayElementCount = arr->getNumElements();
            }

            if (auto* td = dynamic_cast<const TypeDef*>(dt)) {
                DataType* base = td->getBaseDataType();
                typedefBaseId = resolveSnapId(base);
            }

            // Implicit pointers (language-default length) serialize as -1 so
            // the reader rebuilds the suffix-less name instead of resolving
            // getLength() to the default pointer size and creating "*64".
            int dtLen = dt->getLength();
            if (auto* ptr = dynamic_cast<const Pointer*>(dt)) {
                if (ptr->hasLanguageDependantLength()) {
                    dtLen = -1;
                }
            }

            dataTypes.push_back(fb::CreateDataTypeRecordDirect(builder,
                snapIdOf(dt),
                dtName.c_str(),
                catPath.empty() ? nullptr : catPath.c_str(),
                dtLen,
                typeKind.empty() ? nullptr : typeKind.c_str(),
                desc.empty() ? nullptr : desc.c_str(),
                fields.empty() ? nullptr : &fields,
                enumValues.empty() ? nullptr : &enumValues,
                    pointerTargetId > 0 ? pointerTargetId : 0,
                    arrayElementId > 0 ? arrayElementId : 0,
                    arrayElementCount,
                    typedefBaseId > 0 ? typedefBaseId : 0,
                    pack,
                    minAlignment,
                    /*inline_materialized=*/false,
                    funcdefVarArgs));
        }

        // Materialized helper records (see materializeInline above) go after
        // every registered type so path dedup on the read side always finds
        // the registered instance first.
        for (auto& rec : materializedTypes) {
            dataTypes.push_back(rec);
        }
    }

    // Bookmarks
    std::vector<flatbuffers::Offset<fb::BookmarkRecord>> bookmarks;
    if (auto* bm = program.getBookmarkManager()) {
        for (auto* bk : bm->getAllBookmarks()) {
            bookmarks.push_back(fb::CreateBookmarkRecordDirect(builder,
                static_cast<uint64_t>(bk->getAddress().getOffset()),
                nullptr,
                bk->getComment().c_str(),
                bk->getType().c_str()));
        }
    }

    // Equates (name/value; one record per operand reference binding, or a
    // single record with op_index = -1 for equates with no reference bindings)
    std::vector<flatbuffers::Offset<fb::EquateRecord>> equates;
    if (auto* et = program.getEquateTable()) {
        std::map<Equate*, std::vector<std::pair<uint64_t, int16_t>>> bindings;
        for (const auto& b : et->getAllBindings()) {
            if (!b.equate) continue;
            bindings[b.equate].emplace_back(b.addressOffset, b.opIndex);
        }
        for (auto* eq : et->getEquates()) {
            auto it = bindings.find(eq);
            if (it == bindings.end() || it->second.empty()) {
                equates.push_back(fb::CreateEquateRecordDirect(builder,
                    eq->getName().c_str(), 0, -1, eq->getValue()));
            } else {
                for (const auto& binding : it->second) {
                    equates.push_back(fb::CreateEquateRecordDirect(builder,
                        eq->getName().c_str(), binding.first, binding.second,
                        eq->getValue()));
                }
            }
        }
    }

    // External locations
    std::vector<flatbuffers::Offset<fb::ExternalLocationRecord>> extLocs;
    if (auto* em = program.getExternalManager()) {
        for (auto* loc : em->getExternalLocations()) {
            extLocs.push_back(fb::CreateExternalLocationRecordDirect(builder,
                loc->getLabel().c_str(), nullptr,
                loc->getLibraryName().c_str(),
                static_cast<uint64_t>(loc->getAddress().getOffset())));
        }
    }

    // Relocations (status/type/values/bytes/symbol all preserved)
    std::vector<flatbuffers::Offset<fb::RelocationRecord>> relocations;
    if (auto* rt = program.getRelocationTable()) {
        for (auto& reloc : rt->getRelocations()) {
            std::string typeStr = std::to_string(reloc.getType());
            std::string symName = reloc.getSymbolName();
            relocations.push_back(fb::CreateRelocationRecordDirect(builder,
                static_cast<uint64_t>(reloc.getAddress().getOffset()),
                typeStr.c_str(),
                0,
                reloc.hasBytes() ? &reloc.getBytes() : nullptr,
                static_cast<uint8_t>(reloc.getStatus()),
                reloc.getValues().empty() ? nullptr : &reloc.getValues(),
                symName.empty() ? nullptr : symName.c_str()));
        }
    }

    // Function tags (name/comment + tag-to-function assignments)
    std::vector<flatbuffers::Offset<fb::FunctionTagRecord>> functionTags;
    if (auto* ftm = program.getFunctionTagManager()) {
        std::map<long, std::vector<uint64_t>> addressesByTag;
        if (auto* fm = program.getFunctionManager()) {
            auto iter = fm->getFunctions();
            while (iter.hasNext()) {
                Function* func = iter.next();
                if (!func) continue;
                for (auto* tag : func->getTags()) {
                    if (!tag) continue;
                    addressesByTag[tag->getId()].push_back(
                        static_cast<uint64_t>(func->getEntryPoint().getOffset()));
                }
            }
        }
        for (auto* tag : ftm->getAllFunctionTags()) {
            std::vector<uint64_t> addrs;
            auto it = addressesByTag.find(tag->getId());
            if (it != addressesByTag.end()) {
                addrs = it->second;
                std::sort(addrs.begin(), addrs.end());
            }
            functionTags.push_back(fb::CreateFunctionTagRecordDirect(builder,
                tag->getName().c_str(),
                tag->getComment().c_str(),
                addrs.empty() ? nullptr : &addrs));
        }
    }

    // Program context register values (current + defaults)
    std::vector<flatbuffers::Offset<fb::ProgramContextRecord>> programContext;
    if (auto* ctx = dynamic_cast<const ProgramContextImpl*>(program.getProgramContext())) {
        for (const auto& kv : ctx->getRegisterValues()) {
            const RegisterValue* rv = kv.second;
            if (!rv || !kv.first.reg) continue;
            const auto& mask = rv->getMask();
            programContext.push_back(fb::CreateProgramContextRecordDirect(builder,
                kv.first.reg->getName().c_str(),
                static_cast<uint64_t>(kv.first.start.getOffset()),
                std::to_string(rv->getUnsignedOffset()).c_str(),
                static_cast<uint64_t>(kv.first.end.getOffset()),
                mask.empty() ? nullptr : &mask,
                /*is_default=*/false));
        }
        for (const auto& kv : ctx->getDefaultValues()) {
            const RegisterValue* rv = kv.second;
            if (!rv || !kv.first.reg) continue;
            const auto& mask = rv->getMask();
            programContext.push_back(fb::CreateProgramContextRecordDirect(builder,
                kv.first.reg->getName().c_str(),
                static_cast<uint64_t>(kv.first.start.getOffset()),
                std::to_string(rv->getUnsignedOffset()).c_str(),
                static_cast<uint64_t>(kv.first.end.getOffset()),
                mask.empty() ? nullptr : &mask,
                /*is_default=*/true));
        }
    }

    // Entry points (Ghidra's entry pseudo-references, natively stored on the
    // symbol table)
    std::vector<uint64_t> entryPoints;
    if (auto* st = program.getSymbolTable()) {
        for (const Address& addr : st->getExternalEntryPoints()) {
            entryPoints.push_back(static_cast<uint64_t>(addr.getOffset()));
        }
    }

    // Source maps
    std::vector<flatbuffers::Offset<fb::SourceMapEntryRecord>> sourceMapEntries;
    std::vector<flatbuffers::Offset<flatbuffers::String>> sourceFileNames;
    if (auto* srcMgr = program.getSourceFileManager()) {
        for (auto* file : srcMgr->getAllSourceFiles()) {
            if (file) sourceFileNames.push_back(builder.CreateString(file->getPath()));
        }
        if (auto* impl = dynamic_cast<SourceFileManagerImpl*>(srcMgr)) {
            for (const SourceMapEntry& entry : impl->getSourceMapEntriesDirect()) {
                const SourceFile* file = entry.getSourceFile();
                if (!file) continue;
                sourceMapEntries.push_back(fb::CreateSourceMapEntryRecordDirect(builder,
                    static_cast<uint64_t>(entry.getBaseAddress().getOffset()),
                    file->getPath().c_str(),
                    entry.getLineNumber(),
                    entry.getLength()));
            }
        }
    }

    // Metadata
    std::vector<flatbuffers::Offset<fb::MetadataRecord>> metadata;
    for (const auto& kv : program.getMetadata()) {
        metadata.push_back(fb::CreateMetadataRecordDirect(builder,
            kv.first.c_str(), kv.second.c_str()));
    }

    // Module tree (all trees, module/fragment ids, relationships, ranges)
    std::vector<flatbuffers::Offset<fb::TreeRecord>> trees;
    std::vector<flatbuffers::Offset<fb::TreeModuleRecord>> treeModules;
    std::vector<flatbuffers::Offset<fb::TreeFragmentRecord>> treeFragments;
    std::vector<flatbuffers::Offset<fb::TreeRelationshipRecord>> treeRelationships;
    std::vector<flatbuffers::Offset<fb::TreeFragmentRangeRecord>> treeFragmentRanges;
    if (auto* tm = program.getTreeManager()) {
        for (const auto& pair : tm->getModules()) {
            ModuleManager* mm = pair.second.get();
            if (!mm) continue;
            const std::string& treeName = mm->getTreeName();
            trees.push_back(fb::CreateTreeRecordDirect(builder, treeName.c_str(),
                static_cast<uint64_t>(mm->getModificationNumber())));
            for (const auto& mp : mm->getModules()) {
                if (!mp.second) continue;
                treeModules.push_back(fb::CreateTreeModuleRecordDirect(builder,
                    treeName.c_str(), mp.first,
                    mp.second->getName().c_str(), mp.second->getComment().c_str()));
            }
            for (const auto& fp : mm->getFragments()) {
                if (!fp.second) continue;
                treeFragments.push_back(fb::CreateTreeFragmentRecordDirect(builder,
                    treeName.c_str(), fp.first,
                    fp.second->getName().c_str(), fp.second->getComment().c_str()));
            }
            for (const auto& rel : mm->getRawRelationships()) {
                int idx = -1;
                std::vector<long> children = mm->getChildrenIDs(rel.first);
                auto cit = std::find(children.begin(), children.end(), rel.second);
                if (cit != children.end()) {
                    idx = static_cast<int>(cit - children.begin());
                }
                treeRelationships.push_back(fb::CreateTreeRelationshipRecordDirect(builder,
                    treeName.c_str(), rel.first, rel.second, idx));
            }
            for (const auto& fp : mm->getFragments()) {
                if (!fp.second) continue;
                auto* ranges = fp.second->getAddressRanges();
                if (!ranges) continue;
                while (ranges->hasNext()) {
                    const AddressRange& r = ranges->next();
                    treeFragmentRanges.push_back(fb::CreateTreeFragmentRangeRecordDirect(builder,
                        treeName.c_str(), fp.first,
                        static_cast<uint64_t>(r.getMinAddress().getOffset()),
                        static_cast<uint64_t>(r.getMaxAddress().getOffset())));
                }
            }
        }
    }

    // Data organization settings (pointer size, machine alignment, MS
    // bitfield convention, size-alignment table).
    flatbuffers::Offset<fb::DataOrgRecord> dataOrg = 0;
    if (dtm) {
        if (auto* impl = dynamic_cast<DataOrganizationImpl*>(dtm->getDataOrganization())) {
            std::vector<flatbuffers::Offset<fb::SizeAlignmentEntry>> sizeEntries;
            for (int size : impl->getSizes()) {
                sizeEntries.push_back(fb::CreateSizeAlignmentEntry(
                    builder, size, impl->getSizeAlignment(size)));
            }
            dataOrg = fb::CreateDataOrgRecordDirect(builder,
                impl->getPointerSize(), impl->getMachineAlignment(),
                impl->getBitFieldPacking()->useMSConvention(),
                sizeEntries.empty() ? nullptr : &sizeEntries);
        }
    }

    auto snapshot = fb::CreateProgramSnapshotDirect(builder,
        1,
        program.getName().c_str(),
        "",
        langId.empty() ? nullptr : langId.c_str(),
        compId.empty() ? nullptr : compId.c_str(),
        imageBase, minAddr, maxAddr, timestamp, bigEndian,
        memBlocks.empty() ? nullptr : &memBlocks,
        codeUnits.empty() ? nullptr : &codeUnits,
        functions.empty() ? nullptr : &functions,
        conventions.empty() ? nullptr : &conventions,
        symbols.empty() ? nullptr : &symbols,
        comments.empty() ? nullptr : &comments,
        references.empty() ? nullptr : &references,
        dataTypes.empty() ? nullptr : &dataTypes,
        bookmarks.empty() ? nullptr : &bookmarks,
        equates.empty() ? nullptr : &equates,
        extLocs.empty() ? nullptr : &extLocs,
        relocations.empty() ? nullptr : &relocations,
        sourceMapEntries.empty() ? nullptr : &sourceMapEntries,
        functionTags.empty() ? nullptr : &functionTags,
        nullptr,  // user_properties
        programContext.empty() ? nullptr : &programContext,
        metadata.empty() ? nullptr : &metadata,
        trees.empty() ? nullptr : &trees,
        treeModules.empty() ? nullptr : &treeModules,
        treeFragments.empty() ? nullptr : &treeFragments,
        treeRelationships.empty() ? nullptr : &treeRelationships,
        treeFragmentRanges.empty() ? nullptr : &treeFragmentRanges,
        entryPoints.empty() ? nullptr : &entryPoints,
        sourceFileNames.empty() ? nullptr : &sourceFileNames,
        dataOrg);

    builder.Finish(snapshot);

    std::vector<uint8_t> result(
        builder.GetBufferPointer(),
        builder.GetBufferPointer() + builder.GetSize());
    return result;
}

bool SnapshotWriter::writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    return out.good();
}

} // namespace storage
} // namespace ghidra