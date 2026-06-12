#include <ghidra/AnalysisBridge.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/Enum.h>
#include <ghidra/Array.h>
#include <ghidra/Pointer.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/Composite.h>
#include <ghidra/FunctionSignature.h>
#include <ghidra/ParameterDefinition.h>

#include <libdecomp.hh>
#include <funcdata.hh>
#include <fspec.hh>
#include <sleigh_arch.hh>
#include <type.hh>

#include <unordered_set>

namespace ghidra {

AnalysisBridge::AnalysisBridge(ProgramDB* program, ghidra_decompiler::Architecture* arch,
                               std::map<uint64_t, std::string>& symbolNames,
                               uint64_t baseAddr, uint64_t detectedBase, bool userSetBase)
    : program_(program), arch_(arch), symbolNames_(symbolNames),
      baseAddr_(baseAddr), detectedBase_(detectedBase), userSetBase_(userSetBase) {}

AddressSpace* AnalysisBridge::getRamSpace() const {
    if (!program_) return nullptr;
    auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(program_->getAddressFactory());
    if (!addrFactory) return nullptr;
    for (const auto* space : addrFactory->getAddressSpaces()) {
        if (space && space->isMemorySpace())
            return const_cast<AddressSpace*>(space);
    }
    return nullptr;
}

uint64_t AnalysisBridge::mapAddress(uint64_t addr) const {
    if (userSetBase_ && addr >= detectedBase_)
        return baseAddr_ + (addr - detectedBase_);
    return addr;
}

ghidra_decompiler::AddrSpace* AnalysisBridge::getCodeSpace() const {
    return arch_ ? arch_->getDefaultCodeSpace() : nullptr;
}

ghidra_decompiler::Scope* AnalysisBridge::getGlobalScope() const {
    return arch_ ? arch_->symboltab->getGlobalScope() : nullptr;
}

void AnalysisBridge::runAnalysis() {
    if (!program_) return;

    AutoAnalysisManager aam(program_);
    aam.initializeDefaultAnalyzers();
    StubTaskMonitor monitor;
    aam.startAnalysis(&monitor);
    aam.waitForAnalysis(0, &monitor);

    if (std::getenv("ENIGMA_DEBUG")) {
        std::cerr << "[AnalysisBridge] Analysis pipeline complete. Functions: "
                  << program_->getFunctionManager()->getFunctionCount()
                  << ", Symbols: " << program_->getSymbolTable()->getNumSymbols() << "\n";
    }
}

void AnalysisBridge::enrichSymbolNames() {
    if (!program_) return;

    SymbolTable* symTable = program_->getSymbolTable();
    if (!symTable) return;

    // Extract dwarf.* labels -> use name after dot as the real name.
    // Extract all other labels -> use as-is.
    SymbolIterator symIter = symTable->getAllProgramSymbols();
    while (symIter.hasNext()) {
        Symbol* sym = symIter.next();
        if (!sym) continue;
        uint64_t addrVal = static_cast<uint64_t>(sym->getAddress().getOffset());
        if (addrVal == 0) continue;
        std::string name = sym->getName();
        if (name.empty()) continue;

        uint64_t mappedAddr = mapAddress(addrVal);
        if (symbolNames_.find(mappedAddr) != symbolNames_.end()) continue;

        // Handle dwarf.* prefix
        size_t dotPos = name.find('.');
        if (dotPos != std::string::npos && dotPos > 0) {
            std::string prefix = name.substr(0, dotPos);
            if (prefix == "dwarf" && dotPos + 1 < name.size()) {
                std::string realName = name.substr(dotPos + 1);
                symbolNames_[mappedAddr] = realName;
                continue;
            }
        }
        symbolNames_[mappedAddr] = name;
    }
}

void AnalysisBridge::bridgeFunctions() {
    if (!program_ || !arch_) return;

    FunctionManager* fm = program_->getFunctionManager();
    if (!fm) return;

    ghidra_decompiler::AddrSpace* codeSpc = getCodeSpace();
    ghidra_decompiler::Scope* globalScope = getGlobalScope();
    if (!codeSpc || !globalScope) return;

    FunctionIterator fit = fm->getFunctions(true);
    int bridgedCount = 0;

    while (fit.hasNext()) {
        Function* func = fit.next();
        if (!func) continue;

        uint64_t addrVal = static_cast<uint64_t>(func->getEntryPoint().getOffset());
        if (addrVal == 0) continue;

        uint64_t mappedAddr = mapAddress(addrVal);
        std::string funcName = func->getName();
        if (funcName.empty()) continue;

        ghidra_decompiler::Address decompAddr(codeSpc, mappedAddr);

        ghidra_decompiler::Funcdata* existingFd = globalScope->queryFunction(decompAddr);
        if (existingFd) {
            auto it = symbolNames_.find(mappedAddr);
            if (it == symbolNames_.end() ||
                (it->second.rfind("sub_0x", 0) == 0 && funcName.rfind("sub_0x", 0) != 0)) {
                symbolNames_[mappedAddr] = funcName;
            }
            continue;
        }

        try {
            ghidra_decompiler::FunctionSymbol* fsym =
                globalScope->addFunction(decompAddr, funcName);
            if (fsym) {
                symbolNames_[mappedAddr] = funcName;
                bridgedCount++;
            }
        } catch (const ghidra_decompiler::DuplicateFunctionError&) {
            auto it = symbolNames_.find(mappedAddr);
            if (it == symbolNames_.end()) {
                symbolNames_[mappedAddr] = funcName;
            }
        }
    }

    if (std::getenv("ENIGMA_DEBUG") && bridgedCount > 0) {
        std::cerr << "[AnalysisBridge] Bridged " << bridgedCount << " functions into arch->symboltab\n";
    }
}

void AnalysisBridge::bridgeTypes() {
    if (!program_ || !arch_ || !arch_->types) return;

    ghidra_decompiler::TypeFactory* tf = arch_->types;
    DataTypeManager* dtm = program_->getDataTypeManager();
    if (!dtm) return;

    std::vector<DataType*> allTypes = dtm->getDataTypes();
    if (allTypes.empty()) return;

    // Skip built-in types that already exist in TypeFactory as core types
    static const std::unordered_set<std::string> builtInTypes = {
        "void", "bool", "byte", "char", "short", "ushort",
        "int", "uint", "long", "ulong", "longlong", "ulonglong",
        "float", "double", "string", "wchar16", "wchar32",
        "int8", "int16", "int32", "int64",
        "uint8", "uint16", "uint32", "uint64"
    };

    // Bridge cache: ghidra type name -> decompiler Datatype
    // Used to avoid duplicates and resolve circular dependencies
    std::unordered_map<std::string, ghidra_decompiler::Datatype*> bridgeCache;

    // Convert a ghidra::DataType to a ghidra_decompiler::Datatype
    std::function<ghidra_decompiler::Datatype*(DataType*)> convert;
    convert = [&](DataType* dt) -> ghidra_decompiler::Datatype* {
        if (!dt) return nullptr;

        std::string name = dt->getName();
        if (name.empty()) return nullptr;

        // Check cache first
        auto cacheIt = bridgeCache.find(name);
        if (cacheIt != bridgeCache.end()) return cacheIt->second;

        // Check if already in TypeFactory
        ghidra_decompiler::Datatype* existing = tf->findByName(name);
        if (existing) {
            bridgeCache[name] = existing;
            return existing;
        }

        // Skip built-in types — they already exist in TypeFactory with correct definitions
        if (builtInTypes.find(name) != builtInTypes.end()) {
            // Try to find them in TypeFactory again (should exist as core types)
            ghidra_decompiler::Datatype* bt = tf->findByName(name);
            if (bt) bridgeCache[name] = bt;
            return bt;
        }

        // === Typedef ===
        if (auto* td = dynamic_cast<TypeDef*>(dt)) {
            DataType* baseDt = td->getBaseDataType();
            // If base is the same as this typedef, avoid infinite recursion
            if (!baseDt || baseDt == dt) return nullptr;
            ghidra_decompiler::Datatype* baseDecomp = convert(baseDt);
            if (!baseDecomp) return nullptr;
            ghidra_decompiler::Datatype* result = tf->getTypedef(baseDecomp, name, 0, 0);
            bridgeCache[name] = result;
            return result;
        }

        // === Structure ===
        if (auto* st = dynamic_cast<Structure*>(dt)) {
            int length = st->getLength();
            ghidra_decompiler::TypeStruct* ts = tf->getTypeStruct(name);
            // Add to cache immediately for self-referencing fields
            bridgeCache[name] = ts;

            std::vector<ghidra_decompiler::TypeField> fields;
            int numComp = st->getNumComponents();
            for (int i = 0; i < numComp; ++i) {
                DataTypeComponent* comp = st->getComponent(i);
                if (!comp) continue;
                if (comp->isUndefined()) continue;
                DataType* compDt = comp->getDataType();
                if (!compDt) continue;
                ghidra_decompiler::Datatype* compDecomp = convert(compDt);
                if (!compDecomp) continue;
                fields.emplace_back(i, comp->getOffset(),
                    comp->getFieldName(), compDecomp);
            }
            if (!fields.empty()) {
                std::vector<ghidra_decompiler::TypeBitField> bitfields;
                tf->assignRawFields(ts, fields, bitfields);
            }
            return ts;
        }

        // === Union ===
        if (auto* un = dynamic_cast<Union*>(dt)) {
            int length = un->getLength();
            ghidra_decompiler::TypeUnion* tu = tf->getTypeUnion(name);
            bridgeCache[name] = tu;

            std::vector<ghidra_decompiler::TypeField> fields;
            int numComp = un->getNumComponents();
            for (int i = 0; i < numComp; ++i) {
                DataTypeComponent* comp = un->getComponent(i);
                if (!comp) continue;
                if (comp->isUndefined()) continue;
                DataType* compDt = comp->getDataType();
                if (!compDt) continue;
                ghidra_decompiler::Datatype* compDecomp = convert(compDt);
                if (!compDecomp) continue;
                // Union fields all start at offset 0
                fields.emplace_back(i, 0, comp->getFieldName(), compDecomp);
            }
            if (!fields.empty()) {
                tf->assignRawFields(tu, fields);
            }
            return tu;
        }

        // === Enum ===
        if (auto* en = dynamic_cast<Enum*>(dt)) {
            int length = en->getLength();
            ghidra_decompiler::TypeEnum* te = tf->getTypeEnum(name);
            bridgeCache[name] = te;

            std::map<ghidra_decompiler::uintb, std::string> values;
            std::vector<long long> vals = en->getValues();
            std::vector<std::string> names = en->getNames();
            size_t n = std::min(vals.size(), names.size());
            for (size_t i = 0; i < n; ++i) {
                values[static_cast<ghidra_decompiler::uintb>(vals[i])] = names[i];
            }
            if (!values.empty()) {
                tf->setEnumValues(values, te);
            }
            return te;
        }

        // === Array ===
        if (auto* arr = dynamic_cast<Array*>(dt)) {
            DataType* elemDt = arr->getDataType();
            if (!elemDt) return nullptr;
            ghidra_decompiler::Datatype* elemDecomp = convert(elemDt);
            if (!elemDecomp) return nullptr;
            ghidra_decompiler::TypeArray* ta = tf->getTypeArray(arr->getNumElements(), elemDecomp);
            bridgeCache[name] = ta;
            return ta;
        }

        // === Pointer ===
        if (auto* ptr = dynamic_cast<Pointer*>(dt)) {
            DataType* refDt = ptr->getDataType();
            ghidra_decompiler::Datatype* refDecomp = nullptr;
            if (refDt && refDt != dt)
                refDecomp = convert(refDt);
            if (!refDecomp)
                refDecomp = tf->getTypeVoid();
            int ptrSize = ptr->getLength();
            int4 ws = arch_->getDefaultDataSpace()->getWordSize();
            ghidra_decompiler::TypePointer* tp = tf->getTypePointer(ptrSize, refDecomp, ws);
            bridgeCache[name] = tp;
            return tp;
        }

        // Fallback: unknown type kind
        return nullptr;
    };

    // Process all types in a single pass; the recursive convert handles ordering
    int bridgedCount = 0;
    for (DataType* dt : allTypes) {
        if (!dt) continue;
        std::string name = dt->getName();
        if (name.empty() || builtInTypes.find(name) != builtInTypes.end()) continue;
        // Skip root-level built-in type names that clutter the namespace
        // Only bridge types that are not void/bool/etc primitives
        if (dt->getLength() == 0 && name != "void") continue;

        if (convert(dt)) {
            bridgedCount++;
        }
    }

    if (std::getenv("ENIGMA_DEBUG") && bridgedCount > 0) {
        std::cerr << "[AnalysisBridge] Bridged " << bridgedCount << " types into arch->types\n";
    }
}

void AnalysisBridge::bridgeLabels() {
    if (!program_ || !arch_) return;

    SymbolTable* symTable = program_->getSymbolTable();
    if (!symTable) return;

    ghidra_decompiler::AddrSpace* codeSpc = getCodeSpace();
    ghidra_decompiler::Scope* globalScope = getGlobalScope();
    if (!codeSpc || !globalScope) return;

    SymbolIterator symIter = symTable->getAllProgramSymbols();
    int bridgedCount = 0;

    while (symIter.hasNext()) {
        Symbol* sym = symIter.next();
        if (!sym) continue;

        uint64_t addrVal = static_cast<uint64_t>(sym->getAddress().getOffset());
        if (addrVal == 0) continue;

        uint64_t mappedAddr = mapAddress(addrVal);
        if (symbolNames_.find(mappedAddr) != symbolNames_.end()) continue;

        std::string symName = sym->getName();
        if (symName.empty()) continue;

        ghidra_decompiler::Address decompAddr(codeSpc, mappedAddr);
        if (globalScope->queryFunction(decompAddr)) continue;
        if (globalScope->queryCodeLabel(decompAddr)) continue;

        SymbolType symType = sym->getSymbolType();
        if (isFunctionType(symType)) continue;

        try {
            if (symType == SymbolType::LABEL) {
                globalScope->addCodeLabel(decompAddr, symName);
                symbolNames_[mappedAddr] = symName;
                bridgedCount++;
            }
        } catch (...) {
        }
    }

    if (std::getenv("ENIGMA_DEBUG") && bridgedCount > 0) {
        std::cerr << "[AnalysisBridge] Bridged " << bridgedCount << " labels into arch->symboltab\n";
    }
}

void AnalysisBridge::bridgeReadOnlyRanges() {
    if (!program_ || !arch_) return;

    Memory* mem = program_->getMemory();
    if (!mem) return;

    ghidra_decompiler::AddrSpace* dataSpace = arch_->getDefaultDataSpace();
    if (!dataSpace) return;

    int rangeCount = 0;
    for (const auto& block : mem->getBlocks()) {
        if (!block) continue;
        if (block->isWrite() || block->getSize() == 0) continue;

        uint64_t startVal = static_cast<uint64_t>(block->getStart().getOffset());
        uint64_t endVal = static_cast<uint64_t>(block->getEnd().getOffset());

        uint64_t startMapped = mapAddress(startVal);
        uint64_t endMapped = mapAddress(endVal);

        if (endMapped <= startMapped) continue;

        ghidra_decompiler::Range range(dataSpace, startMapped, endMapped);
        arch_->symboltab->setPropertyRange(ghidra_decompiler::Varnode::readonly, range);
        rangeCount++;
    }

    if (std::getenv("ENIGMA_DEBUG") && rangeCount > 0) {
        std::cerr << "[AnalysisBridge] Marked " << rangeCount << " read-only ranges\n";
    }
}

ghidra_decompiler::Datatype* AnalysisBridge::toDecompilerDatatype(DataType* dt) {
    if (!dt || !arch_ || !arch_->types) return nullptr;

    std::string name = dt->getName();
    if (name.empty()) return nullptr;

    // Check cache
    auto cacheIt = typeCache_.find(name);
    if (cacheIt != typeCache_.end()) return cacheIt->second;

    ghidra_decompiler::TypeFactory* tf = arch_->types;

    // Check if already exists in TypeFactory (e.g., from bridgeTypes)
    ghidra_decompiler::Datatype* existing = tf->findByName(name);
    if (existing) {
        typeCache_[name] = existing;
        return existing;
    }

    // === Pointer ===
    if (auto* ptr = dynamic_cast<Pointer*>(dt)) {
        DataType* refDt = ptr->getDataType();
        ghidra_decompiler::Datatype* refDecomp = nullptr;
        if (refDt && refDt != dt)
            refDecomp = toDecompilerDatatype(refDt);
        if (!refDecomp)
            refDecomp = tf->getTypeVoid();
        int ptrSize = ptr->getLength();
        int4 ws = arch_->getDefaultDataSpace()->getWordSize();
        ghidra_decompiler::TypePointer* tp = tf->getTypePointer(ptrSize, refDecomp, ws);
        typeCache_[name] = tp;
        return tp;
    }

    // === Array ===
    if (auto* arr = dynamic_cast<Array*>(dt)) {
        DataType* elemDt = arr->getDataType();
        if (!elemDt) return nullptr;
        ghidra_decompiler::Datatype* elemDecomp = toDecompilerDatatype(elemDt);
        if (!elemDecomp) return nullptr;
        ghidra_decompiler::TypeArray* ta = tf->getTypeArray(arr->getNumElements(), elemDecomp);
        typeCache_[name] = ta;
        return ta;
    }

    // === TypeDef (DWORD, HANDLE, LPVOID, etc.) ===
    if (auto* td = dynamic_cast<TypeDef*>(dt)) {
        DataType* baseDt = td->getBaseDataType();
        if (!baseDt || baseDt == dt) return nullptr;
        ghidra_decompiler::Datatype* baseDecomp = toDecompilerDatatype(baseDt);
        if (!baseDecomp) return nullptr;
        ghidra_decompiler::Datatype* result = tf->getTypedef(baseDecomp, name, 0, 0);
        typeCache_[name] = result;
        return result;
    }

    // === Structure / Union / Enum (should already be in TypeFactory from bridgeTypes) ===
    // If not in cache and not findable by name, try to look up by common names
    // For functions, these are rarely used directly as parameter types without typedefs.

    // === Built-in type matching by name and size ===
    int len = dt->getLength();
    if (name == "void" || name == "Void") return tf->getTypeVoid();
    if (name == "bool" || name == "BOOL" || name == "boolean") return tf->getBase(1, ghidra_decompiler::TYPE_BOOL);
    if (name == "char" || name == "CHAR") return tf->getBase(1, ghidra_decompiler::TYPE_INT);
    if (name == "byte" || name == "BYTE") return tf->getBase(1, ghidra_decompiler::TYPE_UINT);
    if (name == "short" || name == "short int" || name == "SHORT") return tf->getBase(2, ghidra_decompiler::TYPE_INT);
    if (name == "ushort" || name == "WORD" || name == "wchar_t" || name == "WCHAR") return tf->getBase(2, ghidra_decompiler::TYPE_UINT);
    if (name == "int" || name == "int4" || name == "INT" || name == "INT32") return tf->getBase(4, ghidra_decompiler::TYPE_INT);
    if (name == "uint" || name == "uint4" || name == "UINT" || name == "DWORD" || name == "ULONG" || name == "UINT32") return tf->getBase(4, ghidra_decompiler::TYPE_UINT);
    if (name == "long" || name == "LONG") return tf->getBase(4, ghidra_decompiler::TYPE_INT);
    if (name == "ulong" || name == "ULONG") return tf->getBase(4, ghidra_decompiler::TYPE_UINT);
    if (name == "long long" || name == "int8" || name == "LONGLONG" || name == "INT64") return tf->getBase(8, ghidra_decompiler::TYPE_INT);
    if (name == "uint8" || name == "ULONGLONG" || name == "DWORD64" || name == "UINT64" || name == "size_t" || name == "SIZE_T") return tf->getBase(8, ghidra_decompiler::TYPE_UINT);
    if (name == "float" || name == "FLOAT") return tf->getBase(4, ghidra_decompiler::TYPE_FLOAT);
    if (name == "double" || name == "DOUBLE") return tf->getBase(8, ghidra_decompiler::TYPE_FLOAT);

    // === Fallback: use size-based type ===
    if (len == 1) return tf->getBase(1, ghidra_decompiler::TYPE_UINT);
    if (len == 2) return tf->getBase(2, ghidra_decompiler::TYPE_UINT);
    if (len == 4) return tf->getBase(4, ghidra_decompiler::TYPE_UINT);
    if (len == 8) return tf->getBase(8, ghidra_decompiler::TYPE_UINT);

    return nullptr;
}

void AnalysisBridge::bridgeSignatures() {
    if (!program_ || !arch_) return;
    FunctionManager* fm = program_->getFunctionManager();
    if (!fm) return;

    ghidra_decompiler::AddrSpace* codeSpc = getCodeSpace();
    ghidra_decompiler::Scope* globalScope = getGlobalScope();
    if (!codeSpc || !globalScope) return;

    FunctionIterator fit = fm->getFunctions(true);
    int totalFuncs = 0, ccSet = 0;

    while (fit.hasNext()) {
        Function* func = fit.next();
        if (!func) continue;
        uint64_t addrVal = static_cast<uint64_t>(func->getEntryPoint().getOffset());
        if (addrVal == 0) continue;
        uint64_t mappedAddr = mapAddress(addrVal);
        ghidra_decompiler::Address decompAddr(codeSpc, mappedAddr);
        ghidra_decompiler::Funcdata* fd = globalScope->queryFunction(decompAddr);
        if (!fd) continue;
        totalFuncs++;

        if (func->hasNoReturn())
            fd->getFuncProto().setNoReturn(true);
    }

    if (std::getenv("ENIGMA_DEBUG"))
        std::cerr << "[AnalysisBridge] bridgeSignatures: " << totalFuncs << " funcs, "
                  << ccSet << " cc set\n";
}

void AnalysisBridge::execute() {
    runAnalysis();
    enrichSymbolNames();
    bridgeFunctions();
    bridgeTypes();
    bridgeSignatures();
    bridgeLabels();
    bridgeReadOnlyRanges();
}

} // namespace ghidra
