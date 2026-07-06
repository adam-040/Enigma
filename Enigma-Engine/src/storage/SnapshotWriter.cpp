#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/storage/Repository.h>
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
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/DataType.h>
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
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include "program_generated.h"
#include <flatbuffers/flatbuffers.h>
#include <fstream>
#include <ctime>
#include <vector>
#include <algorithm>
#include <limits>

namespace ghidra {
namespace storage {

namespace fb = fbschema;

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

    // Get DataTypeManagerImpl for type ID lookups throughout serialization
    auto* dtm = program.getDataTypeManager();
    auto* dtmImpl = dynamic_cast<const DataTypeManagerImpl*>(dtm);

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

    // Code units — no simple all-code-units iterator on Listing, skip

    // Functions
    std::vector<flatbuffers::Offset<fb::FunctionRecord>> functions;
    if (auto* fm = program.getFunctionManager()) {
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
                long paramDtId = 0;
                if (paramDt && dtmImpl) paramDtId = dtmImpl->getDataTypeId(paramDt);
                params.push_back(fb::CreateParamRecordDirect(builder,
                    param->getName().c_str(),
                    paramDt ? paramDt->getName().c_str() : nullptr,
                    static_cast<uint64_t>(paramDtId),
                    -1));
            }
            DataType* retDt = func->getReturnType();
            long retDtId = 0;
            if (retDt && dtmImpl) retDtId = dtmImpl->getDataTypeId(retDt);
            functions.push_back(fb::CreateFunctionRecordDirect(builder,
                func->getName().c_str(),
                static_cast<uint64_t>(func->getEntryPoint().getOffset()),
                bodyRanges.empty() ? nullptr : &bodyRanges,
                func->getCallingConvention() ? func->getCallingConvention()->getName().c_str() : nullptr,
                retDt ? retDt->getName().c_str() : nullptr,
                static_cast<uint64_t>(retDtId),
                static_cast<uint64_t>(func->getStackFrameSize()),
                func->isExternal(),
                func->hasNoReturn(),
                func->isInline(),
                func->getCallFixup().empty() ? nullptr : func->getCallFixup().c_str(),
                static_cast<uint8_t>(func->getSignatureSource()),
                nullptr,
                params.empty() ? nullptr : &params));
        }
    }

    // Symbols
    std::vector<flatbuffers::Offset<fb::SymbolRecord>> symbols;
    if (auto* st = program.getSymbolTable()) {
        auto it = st->getAllProgramSymbols(true);
        while (it.hasNext()) {
            Symbol* sym = it.next();
            std::string ns;
            if (sym->getParentNamespace()) {
                ns = sym->getParentNamespace()->getName();
            }
            symbols.push_back(fb::CreateSymbolRecordDirect(builder,
                sym->getName().c_str(),
                ns.empty() ? nullptr : ns.c_str(),
                static_cast<uint64_t>(sym->getAddress().getOffset()),
                symbolTypeToString(sym->getSymbolType()).c_str(),
                sym->isPrimary()));
        }
    }

    // Comments — no dedicated CommentManager with iteration API, skip

    // References
    std::vector<flatbuffers::Offset<fb::ReferenceRecord>> references;
    if (auto* rm = program.getReferenceManager()) {
        for (auto* ref : rm->getAllReferences()) {
            references.push_back(fb::CreateReferenceRecordDirect(builder,
                static_cast<uint64_t>(ref->getFromAddress().getOffset()),
                static_cast<uint64_t>(ref->getToAddress().getOffset()),
                nullptr,
                ref->isPrimary()));
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

            long dtId = dtmImpl ? dtmImpl->getDataTypeId(dt) : 0;

            // Determine type kind by dynamic type
            std::string typeKind;
            if (dynamic_cast<const Structure*>(dt)) typeKind = "struct";
            else if (dynamic_cast<const Union*>(dt)) typeKind = "union";
            else if (dynamic_cast<const Enum*>(dt)) typeKind = "enum";
            else if (dynamic_cast<const Pointer*>(dt)) typeKind = "pointer";
            else if (dynamic_cast<const Array*>(dt)) typeKind = "array";
            else if (dynamic_cast<const TypeDef*>(dt)) typeKind = "typedef";
            else typeKind = "builtin";

            // Structural fields
            std::vector<flatbuffers::Offset<fb::StructField>> fields;
            std::vector<flatbuffers::Offset<fb::EnumValue>> enumValues;
            uint64_t pointerTargetId = 0;
            uint64_t arrayElementId = 0;
            int arrayElementCount = 0;
            uint64_t typedefBaseId = 0;

            // Struct/Union: serialize components
            if (auto* comp = dynamic_cast<const Composite*>(dt)) {
                int nc = comp->getNumComponents();
                for (int i = 0; i < nc; ++i) {
                    DataTypeComponent* dc = comp->getComponent(i);
                    if (!dc) continue;
                    std::string fieldName = dc->getFieldName();
                    int offset = dc->getOffset();
                    DataType* fieldDt = dc->getDataType();
                    long fieldDtId = fieldDt && dtmImpl ? dtmImpl->getDataTypeId(fieldDt) : 0;
                    auto fn = builder.CreateString(fieldName);
                    fields.push_back(fb::CreateStructField(builder, fn, offset, fieldDtId));
                }
            }

            // Enum: serialize values
            if (auto* en = dynamic_cast<const Enum*>(dt)) {
                auto names = en->getNames();
                auto values = en->getValues();
                size_t n = std::min(names.size(), values.size());
                for (size_t i = 0; i < n; ++i) {
                    auto evName = builder.CreateString(names[i]);
                    enumValues.push_back(fb::CreateEnumValue(builder, evName, values[i]));
                }
            }

            // Pointer: target type ID
            if (auto* ptr = dynamic_cast<const Pointer*>(dt)) {
                DataType* target = ptr->getDataType();
                if (target && dtmImpl)
                    pointerTargetId = static_cast<uint64_t>(dtmImpl->getDataTypeId(target));
            }

            // Array: element type + count
            if (auto* arr = dynamic_cast<const Array*>(dt)) {
                DataType* elem = arr->getDataType();
                if (elem && dtmImpl)
                    arrayElementId = static_cast<uint64_t>(dtmImpl->getDataTypeId(elem));
                arrayElementCount = arr->getNumElements();
            }

            // Typedef: base type ID
            if (auto* td = dynamic_cast<const TypeDef*>(dt)) {
                DataType* base = td->getBaseDataType();
                if (base && dtmImpl)
                    typedefBaseId = static_cast<uint64_t>(dtmImpl->getDataTypeId(base));
            }

            dataTypes.push_back(fb::CreateDataTypeRecordDirect(builder,
                static_cast<uint64_t>(dtId),
                dtName.c_str(),
                catPath.empty() ? nullptr : catPath.c_str(),
                dt->getLength(),
                typeKind.empty() ? nullptr : typeKind.c_str(),
                desc.empty() ? nullptr : desc.c_str(),
                fields.empty() ? nullptr : &fields,
                enumValues.empty() ? nullptr : &enumValues,
                pointerTargetId > 0 ? pointerTargetId : 0,
                arrayElementId > 0 ? arrayElementId : 0,
                arrayElementCount,
                typedefBaseId > 0 ? typedefBaseId : 0));
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

    // Equates
    std::vector<flatbuffers::Offset<fb::EquateRecord>> equates;
    if (auto* et = program.getEquateTable()) {
        for (auto* eq : et->getEquates()) {
            equates.push_back(fb::CreateEquateRecordDirect(builder,
                eq->getName().c_str(),
                0, 0, eq->getValue()));
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

    // Relocations
    std::vector<flatbuffers::Offset<fb::RelocationRecord>> relocations;
    if (auto* rt = program.getRelocationTable()) {
        for (auto& reloc : rt->getRelocations()) {
            std::string typeStr = std::to_string(reloc.getType());
            relocations.push_back(fb::CreateRelocationRecordDirect(builder,
                static_cast<uint64_t>(reloc.getAddress().getOffset()),
                typeStr.c_str(),
                0,
                reloc.hasBytes() ? &reloc.getBytes() : nullptr));
        }
    }

    // Source map entries — no simple all-entries API, skip

    // Function tags
    std::vector<flatbuffers::Offset<fb::FunctionTagRecord>> functionTags;
    if (auto* ftm = program.getFunctionTagManager()) {
        for (auto* tag : ftm->getAllFunctionTags()) {
            functionTags.push_back(fb::CreateFunctionTagRecordDirect(builder,
                tag->getName().c_str(),
                tag->getComment().c_str(),
                nullptr));
        }
    }

    // User properties — no "get all" API on PropertyMapManager, skip
    // Program context — no "get all values" API on ProgramContext, skip

    auto snapshot = fb::CreateProgramSnapshotDirect(builder,
        1,
        program.getName().c_str(),
        "",
        langId.empty() ? nullptr : langId.c_str(),
        compId.empty() ? nullptr : compId.c_str(),
        imageBase, minAddr, maxAddr, timestamp, bigEndian,
        memBlocks.empty() ? nullptr : &memBlocks,
        nullptr,  // code_units
        functions.empty() ? nullptr : &functions,
        symbols.empty() ? nullptr : &symbols,
        nullptr,  // comments
        references.empty() ? nullptr : &references,
        dataTypes.empty() ? nullptr : &dataTypes,
        bookmarks.empty() ? nullptr : &bookmarks,
        equates.empty() ? nullptr : &equates,
        extLocs.empty() ? nullptr : &extLocs,
        relocations.empty() ? nullptr : &relocations,
        nullptr,  // source_map_entries
        functionTags.empty() ? nullptr : &functionTags,
        nullptr,  // user_properties
        nullptr); // program_context

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
