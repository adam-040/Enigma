#pragma once

#include <ghidra/ProgramDB.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Listing.h>
#include <ghidra/DataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Structure.h>
#include <ghidra/Union.h>
#include <ghidra/Enum.h>
#include <map>
#include <string>
#include <unordered_map>

namespace ghidra_decompiler {
class Architecture;
class AddrSpace;
class Scope;
class Datatype;
class TypeFactory;
}

namespace ghidra {

class AnalysisBridge {
public:
    AnalysisBridge(ProgramDB* program, ghidra_decompiler::Architecture* arch,
                   std::map<uint64_t, std::string>& symbolNames,
                   uint64_t baseAddr, uint64_t detectedBase, bool userSetBase);

    void execute();
    void runAnalysis();
    void bridgeFunctions();
    void bridgeTypes();
    void bridgeLabels();
    void bridgeReadOnlyRanges();
    void bridgeSignatures();
    void enrichSymbolNames();

private:
    ProgramDB* program_;
    ghidra_decompiler::Architecture* arch_;
    std::map<uint64_t, std::string>& symbolNames_;
    uint64_t baseAddr_;
    uint64_t detectedBase_;
    bool userSetBase_;

    // Cache for ghidra DataType* -> decompiler Datatype* conversion
    std::unordered_map<std::string, ghidra_decompiler::Datatype*> typeCache_;

    AddressSpace* getRamSpace() const;
    uint64_t mapAddress(uint64_t addr) const;
    ghidra_decompiler::AddrSpace* getCodeSpace() const;
    ghidra_decompiler::Scope* getGlobalScope() const;
    ghidra_decompiler::Datatype* toDecompilerDatatype(DataType* dt);
};

} // namespace ghidra
