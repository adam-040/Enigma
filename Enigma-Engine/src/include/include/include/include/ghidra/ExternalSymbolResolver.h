/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/// \file ExternalSymbolResolver.h
/// \brief Resolves external symbols to their library namespaces
/// Translated from: ghidra.program.util.ExternalSymbolResolver
#pragma once

#include <ghidra/Program.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>

namespace ghidra {

class Library;
class MessageLog;

class ExternalSymbolResolver {
public:
    ExternalSymbolResolver(Program* program);
    ~ExternalSymbolResolver();

    void addProgramToFixup(Program* program);
    void fixUnresolvedExternalSymbols();
    bool hasProblemLibraries() const { return !problemLibraries_.empty(); }
    void logInfo(std::function<void(const std::string&)> logger, bool shortSummary);

private:
    struct ProgramSymbolResolver {
        Program* program;
        std::string programPath;
        int externalSymbolCount = 0;
        std::vector<long> unresolvedExternalFunctionIds;
        struct ExtLibInfo {
            Library* lib;
            std::string problem;
            std::vector<std::string> resolvedSymbols;
        };
        std::vector<ExtLibInfo> extLibs;

        ProgramSymbolResolver(Program* p, const std::string& path)
            : program(p), programPath(path) {}

        int getResolvedSymbolCount() const;
        void log(std::function<void(const std::string&)> logger, bool shortSummary);
        bool hasSomeLibrariesConfigured() const;
        void resolveExternalSymbols();
        std::vector<long> getUnresolvedExternalFunctionIds();
        std::vector<ExtLibInfo> getLibsToSearch();
        void resolveSymbolsToLibrary(ExtLibInfo& extLib);
    };

    std::vector<std::unique_ptr<ProgramSymbolResolver>> programsToFix_;
    std::vector<std::string> problemLibraries_;
    Program* program_;
};

} // namespace ghidra
