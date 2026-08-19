/* ###
 * IP: Enigma Engine (original work)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GzfProgramImporter.h
/// \brief Imports a Ghidra program database (.gbf) into a fresh ProgramDB.
///
/// Populates, in restore order, the managers that Ghidra itself writes:
/// program info, calling conventions, memory blocks (incl. file bytes and
/// chained sub-buffers), instructions (via prototypes + disassembly),
/// symbols (namespaces, labels, functions), thunks and comments.
///
/// Phase 3a scope per PLAN/Enigma_Ecosystem.md: listing + symbols + memory.
/// Data units, datatypes, references, relocations, bookmarks and module
/// tree are NOT populated yet. External libraries, locations, and references
/// are restored from the Symbols and FROM REFS tables.
#pragma once

#include <ghidra/ProgramDB.h>
#include <ghidra/BuiltIn.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/DataType.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/Settings.h>
#include <ghidra/import/GbfReader.h>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <typeinfo>
#include <vector>

namespace ghidra {

class Disassembler;

class GzfProgramImporter {
public:
    struct Stats {
        int programRecords = 0;
        int metadataRecords = 0;
        int memoryBlocks = 0;
        int subMemoryBlocks = 0;
        int fileBytes = 0;
        int prototypes = 0;
        int instructions = 0;
        int disassemblyFailures = 0;
        int namespaces = 0;
        int labels = 0;
        int functions = 0;
        int thunks = 0;
        int commentsApplied = 0;
        int commentsSkippedNoAddress = 0;
        int references = 0;              // memory refs created
        int refsExternTarget = 0;        // external-space targets with no known location
        int refsEntryPoint = 0;          // refs from the entry-point record
        int refsUnknownSpace = 0;        // refs outside image/external space
        int refsWithSymbolId = 0;
        int refsWithOffsetOrShift = 0;
        int refsBadRecords = 0;
        int externalLibraries = 0;
        int externalLocations = 0;
        int externalReferences = 0;
        int images = 0;

        // Data types phase (P3g)
        int categories = 0;
        int builtins = 0;
        int builtinPlaceholders = 0;     // engine has no class for the corpus builtin
        int builtinAliased = 0;          // corpus id aliased to an engine-builtin instance
        int composites = 0;
        int components = 0;
        int enums = 0;
        int enumValues = 0;
        int functionDefs = 0;
        int functionParams = 0;
        int pointers = 0;
        int typedefs = 0;
        int arrays = 0;
        int datatypeUnresolvedRefs = 0;  // component/param/typedef/array base not resolvable
        int componentOffsetMismatches = 0;

        // Data units phase (P3g)
        int dataUnits = 0;
        int dataConflicts = 0;           // address already has an instruction/data unit
        int dataUnresolvedType = 0;
        int dataUnresolvedLength = 0;
        int dataPlaceholderLengths = 0;  // dynamic placeholder lengths computed by scan
        int dataTerminatedStrings = 0;
        int dataUnwindInfo = 0;
        int dataRichHeader = 0;

        // Functions phase additions
        int functionReturnTypes = 0;
        int functionInline = 0;

        // Register context phase (prototype contexts + register value maps)
        int contextRecords = 0;        // ContextTable records validated
        int contextRecordsBad = 0;     // ContextTable records failing validation
        int registerValueRanges = 0;   // "Range Map - Register_*" records applied
        int registerValueBad = 0;      // range-map records failing decode

        // Bookmarks phase (P3i)
        int bookmarkTypes = 0;         // "Bookmark Types" records
        int bookmarks = 0;             // bookmark records applied
        int bookmarksBad = 0;          // bookmarks failing decode / no type

        // Relocations phase (P3i)
        int relocations = 0;           // "Relocations" records applied
        int relocationsBad = 0;        // relocations failing decode
        int relocationsStatusClamped = 0;  // records kept; Ghidra-only status clamped

        // Module tree phase (P3i)
        int trees = 0;                 // "Trees" records restored
        int modules = 0;               // module records loaded
        int fragments = 0;             // fragment records loaded
        int moduleRelationships = 0;   // parent/child relationship records
        int fragmentRanges = 0;        // fragment address range records
        int moduleTreeBad = 0;         // module-tree records failing decode

        // Function scopes phase (P3i)
        int scopeRanges = 0;           // "SCOPE ADDRESSES" range records read
        int functionsWithScopes = 0;   // functions whose body was restored
        int scopeBad = 0;              // scope records failing decode / unknown id

        // Analytical fidelity phase (P3j)
        int repeatableComments = 0;    // repeatable comments stored in their own slot
        int entryPoints = 0;           // entry refs -> SymbolTable external entry points
        int callFixups = 0;            // "Property Map - CallFixup" -> function call fixups
        int contextDefaults = 0;       // ContextTable value applied as default register context
        int sourceFiles = 0;           // "SourceFiles" records restored
        int sourceMapEntries = 0;      // "SourceMap" records restored
        int sourceMapBad = 0;          // source-map records failing decode
        int variableStorages = 0;      // "Variable Storage" hashes decoded
        int parameters = 0;            // parameter symbols restored onto functions
        int localVariables = 0;        // local-variable symbols restored onto functions
        int variablesBad = 0;          // variable records failing decode / resolve

        // Equates phase (P3j)
        int equates = 0;               // "Equates" records restored
        int equateReferences = 0;      // "Equate References" records applied
        int equatesBad = 0;            // equate / reference records failing decode

        // Function tags phase (P3j)
        int functionTags = 0;          // "Function Tags" records restored
        int functionTagsBad = 0;       // tag records failing decode / empty name
        int functionTagAssignments = 0;  // "Function Tag Map" records applied
        int functionTagAssignmentsBad = 0;  // assignments with unknown tag/function id

        // Original-file phase: bytes recovered from the "File Bytes" table
        // (enables patched-binary export for imported programs).
        int fileBytesRestored = 0;     // original file bytes recovered
    };

    explicit GzfProgramImporter(const GbfReader& reader);

    /** Imports into a new ProgramDB named programName. Throws std::runtime_error on fatal errors. */
    std::unique_ptr<ProgramDB> import(const std::string& programName);

    const Stats& getStats() const { return stats_; }
    const std::vector<std::string>& getWarnings() const { return warnings_; }

    /// Original file bytes recovered from the "File Bytes" table (empty if
    /// the project stores none, e.g. image-only imports).  Lets the GUI
    /// rebuild an export-capable loader for imported programs.
    const std::vector<uint8_t>& getOriginalFileBytes() const { return originalFileBytes_; }
    const std::string& getOriginalFileName() const { return originalFileName_; }

private:
    const GbfReader& reader_;
    Stats stats_;

    /// Original file content recovered from the "File Bytes" table, used to
    /// rebuild an export loader for the imported program.
    std::vector<uint8_t> originalFileBytes_;
    std::string originalFileName_;

    /// External-space symbol materialized from the Symbols table: the address
    /// key's low 32 bits are the offset in the EXTERNAL space.
    struct ImportedExternalLocation {
        std::string libraryName;
        std::string label;
        Address address;
    };
    std::map<uint64_t, ImportedExternalLocation> externalLocationsByKey_;
    std::vector<std::string> warnings_;

    /// Corpus datatype id -> owned DataType, resolved from the data type
    /// tables (P3g).  Ids are 64-bit (2^56 type tag + ordinal).
    std::map<int64_t, DataType*> datatypesById_;

    /// Corpus function id (the function symbol's id) -> Function, populated
    /// by the functions phase; consumed by the function scopes phase.
    std::map<int64_t, Function*> functionsById_;

    /// Effective image base parsed from the Program table ("Image Offset" in
    /// Ghidra 12, legacy "Image Base").  Ghidra stores image-space addresses
    /// as image-relative (RVA) address-map keys, so every imported image
    /// address is materialized at rva + imageBase_.
    int64_t imageBase_ = 0;

    /// Image-space address for a Ghidra image-relative offset (the low 32
    /// bits of an address-map key in the default space, base index 0).
    Address imageAddress(AddressSpace* space, uint64_t rva) const {
        return Address(space,
                       static_cast<int64_t>(static_cast<uint64_t>(imageBase_) + rva));
    }

    /// Address-map key (type4|baseIndex28|offset32) -> engine image address:
    /// the image-relative offset (low 32 bits) plus the effective image base.
    /// Key bytes are big-endian (GbfReader record keys).
    uint64_t keyToImageOffset(const std::vector<uint8_t>& key) const {
        int64_t v = 0;
        for (uint8_t b : key) {
            v = (v << 8) | b;
        }
        return (static_cast<uint64_t>(v) & 0xFFFFFFFFull) +
               static_cast<uint64_t>(imageBase_);
    }

    void warn(const std::string& msg) { warnings_.push_back(msg); }

    std::unique_ptr<Disassembler> makeDisassembler(ProgramDB* program) const;
    void importPhase(const std::function<void()>& fn, const char* phaseName);
    void importCallingConventions(
        ProgramDB* program, std::map<int64_t, std::string>& callingConventionsById);
    void importMemoryBlocks(ProgramDB* program);
    void importFileBytes();
    void importInstructions(ProgramDB* program);
    void importSymbols(ProgramDB* program);
    void importFunctions(ProgramDB* program,
                         const std::map<int64_t, std::string>& callingConventionsById);
    void importComments(ProgramDB* program);
    void importReferences(ProgramDB* program);
    void importContextTable(ProgramDB* program);
    void importRegisterValueMaps(ProgramDB* program);
    void importBookmarks(ProgramDB* program);
    void importRelocations(ProgramDB* program);
    void importModuleTree(ProgramDB* program);
    void importFunctionScopes(ProgramDB* program);
    void importFunctionTags(ProgramDB* program);
    void importMetadata(ProgramDB* program);
    void importEntryPoints(ProgramDB* program);
    void importCallFixups(ProgramDB* program);
    void importSourceMaps(ProgramDB* program);
    void importVariables(ProgramDB* program);

    // P3g: data types + data units
    void importDataTypes(
        ProgramDB* program,
        const std::map<int64_t, std::string>& callingConventionsById);
    void importData(ProgramDB* program);
    void importEquates(ProgramDB* program);
    DataType* registerDataType(DataTypeManager* dtm, DataType* dt, int64_t id);
    DataType* resolveDataType(int64_t id) const;
    CategoryPath categoryPathFor(DataTypeManager* dtm, int64_t categoryId) const;
    int computeDataLength(ProgramDB* program, const Address& addr, DataType* dt);
    int scanTerminatedStringLength(ProgramDB* program, const Address& addr, int charSize);
    int computePEx64UnwindInfoLength(ProgramDB* program, const Address& addr);
    int computeRichHeaderLength(ProgramDB* program, const Address& addr);

    /// Placeholder builtin for corpus builtin classes the engine does not
    /// implement (Guid/MUIResource/PERich/PEx64UnwindInfo).  Fixed length 1;
    /// data units of dynamic placeholders pass an explicit length.
    class PlaceholderDataType : public BuiltIn {
    public:
        PlaceholderDataType(DataTypeManager* dtm, const std::string& name, int length)
            : BuiltIn(CategoryPath::ROOT(), name, dtm), length_(length) {}
        int getLength() const override { return length_; }
        int getAlignedLength() const override { return length_; }
        bool hasLanguageDependantLength() const override { return length_ <= 0; }
        DataType* clone(DataTypeManager* dtm) const override {
            return new PlaceholderDataType(dtm, getName(), length_);
        }
        DataType* copy(DataTypeManager* dtm) const override {
            return new PlaceholderDataType(dtm, getName(), length_);
        }
        std::string getDescription() const override {
            return "Placeholder for a builtin class not implemented by the engine";
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
    };

    struct PendingComposite {
        int64_t id = 0;
        bool isUnion = false;
        std::string name;
        std::string comment;
        int64_t categoryId = 0;
        int length = 0;
        int pack = 0;
        int minAlignment = 0;
    };
    std::map<int64_t, PendingComposite> pendingComposites_;
    struct PendingComponent {
        int64_t parent = 0;
        int offset = 0;
        int64_t dtId = 0;
        std::string name;
        std::string comment;
        int size = 0;
        int ordinal = 0;
    };
    std::vector<PendingComponent> pendingComponents_;

    struct PendingEnumValue {
        int64_t enumId = 0;
        std::string name;
        int64_t value = 0;
        std::string comment;
    };
    std::vector<PendingEnumValue> pendingEnumValues_;

    struct PendingFunctionParam {
        int64_t parent = 0;
        int64_t dtId = 0;
        std::string name;
        std::string comment;
        int ordinal = 0;
    };
    std::vector<PendingFunctionParam> pendingFunctionParams_;

    struct PendingTypedef {
        int64_t id = 0;
        int64_t baseId = 0;
        std::string name;
        int64_t categoryId = 0;
    };
    std::vector<PendingTypedef> pendingTypedefs_;

    struct PendingPointer {
        int64_t id = 0;
        int64_t baseId = 0;
        int64_t categoryId = 0;
        int length = 0;
    };
    std::vector<PendingPointer> pendingPointers_;

    struct PendingArray {
        int64_t id = 0;
        int64_t baseId = 0;
        int64_t categoryId = 0;
        int dimension = 0;
        int elementLength = 0;
    };
    std::vector<PendingArray> pendingArrays_;
};

}  // namespace ghidra
