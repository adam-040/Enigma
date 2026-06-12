#pragma once
#include <ghidra/ProgramDB.h>
#include <string>
#include <cstdint>

namespace ghidra {
namespace storage {

class IndexManager {
public:
    /// Rebuild the LMDB index from a ProgramDB's symbols and functions.
    static bool rebuildFromProgramDB(const std::string& repoPath, const ProgramDB& program);

    /// Add a symbol to the index.
    static bool addSymbol(const std::string& repoPath, const std::string& name, uint64_t address);

    /// Remove a symbol from the index.
    static bool removeSymbol(const std::string& repoPath, const std::string& name);

    /// Look up a symbol by name, returns address or 0 if not found.
    static uint64_t lookupSymbol(const std::string& repoPath, const std::string& name);

    /// Look up a symbol by address, returns name or empty string.
    static std::string lookupSymbolByAddress(const std::string& repoPath, uint64_t address);

    /// Add a function to the index.
    static bool addFunction(const std::string& repoPath, const std::string& name, uint64_t entryPoint);

    /// Remove a function from the index.
    static bool removeFunction(const std::string& repoPath, const std::string& name);

    /// Look up a function by name, returns entry point address or 0.
    static uint64_t lookupFunction(const std::string& repoPath, const std::string& name);

    /// Look up a function by entry point, returns name or empty string.
    static std::string lookupFunctionByEntry(const std::string& repoPath, uint64_t entryPoint);

    /// Clear all entries from the index.
    static bool clear(const std::string& repoPath);
};

} // namespace storage
} // namespace ghidra
