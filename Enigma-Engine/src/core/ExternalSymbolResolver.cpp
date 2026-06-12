/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/// \file ExternalSymbolResolver.cpp
/// \brief Resolves external symbols to their library namespaces
#include <ghidra/ExternalSymbolResolver.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/Library.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolType.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

ExternalSymbolResolver::ExternalSymbolResolver(Program* program)
    : program_(program) {}

ExternalSymbolResolver::~ExternalSymbolResolver() = default;

void ExternalSymbolResolver::addProgramToFixup(Program* program) {
    std::string path = program->getExecutableFormat();
    programsToFix_.push_back(std::make_unique<ProgramSymbolResolver>(program, path));
}

void ExternalSymbolResolver::fixUnresolvedExternalSymbols() {
    for (auto& psr : programsToFix_) {
        psr->resolveExternalSymbols();
    }
}

void ExternalSymbolResolver::logInfo(std::function<void(const std::string&)> logger, bool shortSummary) {
    for (auto& psr : programsToFix_) {
        psr->log(logger, shortSummary);
    }
}

// --- ProgramSymbolResolver ---

int ExternalSymbolResolver::ProgramSymbolResolver::getResolvedSymbolCount() const {
    return externalSymbolCount - static_cast<int>(unresolvedExternalFunctionIds.size());
}

void ExternalSymbolResolver::ProgramSymbolResolver::log(
    std::function<void(const std::string&)> logger, bool shortSummary) {

    bool changed = static_cast<int>(unresolvedExternalFunctionIds.size()) != externalSymbolCount;
    if (extLibs.empty() && externalSymbolCount == 0) {
        return;
    }
    else if (!changed && !hasSomeLibrariesConfigured()) {
        logger("Resolving External Symbols of [" + programPath + "] - " +
               std::to_string(externalSymbolCount) + " unresolved symbols, no external libraries configured - skipping");
        return;
    }

    logger("Resolving External Symbols of [" + programPath + "]" +
           (shortSummary ? " - Summary" : ""));
    logger("\t" + std::to_string(getResolvedSymbolCount()) +
           " external symbols resolved, " +
           std::to_string(unresolvedExternalFunctionIds.size()) + " remain unresolved");

    for (auto& extLib : extLibs) {
        std::string libPath = extLib.lib ? extLib.lib->getAssociatedProgramPath() : "missing";
        if (!extLib.problem.empty()) {
            logger("\t[" + extLib.lib->getName() + "] -> " + libPath + ", " + extLib.problem);
        }
        else if (!libPath.empty()) {
            logger("\t[" + extLib.lib->getName() + "] -> " + libPath + ", " +
                   std::to_string(extLib.resolvedSymbols.size()) + " new symbols resolved");
        }
        else {
            logger("\t[" + extLib.lib->getName() + "] -> " + libPath);
        }
        if (!shortSummary) {
            for (auto& symName : extLib.resolvedSymbols) {
                logger("\t\t[" + symName + "]");
            }
        }
    }
    if (!shortSummary && changed) {
        if (!unresolvedExternalFunctionIds.empty()) {
            logger("\tUnresolved remaining " +
                   std::to_string(unresolvedExternalFunctionIds.size()) + ":");
            SymbolTable* symbolTable = program->getSymbolTable();
            for (long symId : unresolvedExternalFunctionIds) {
                Symbol* s = symbolTable->getSymbol(symId);
                if (s) {
                    logger("\t\t[" + s->getName() + "]");
                }
            }
        }
    }
}

bool ExternalSymbolResolver::ProgramSymbolResolver::hasSomeLibrariesConfigured() const {
    for (auto& extLib : extLibs) {
        if (!extLib.problem.empty() || (extLib.lib && !extLib.lib->getAssociatedProgramPath().empty())) {
            return true;
        }
    }
    return false;
}

void ExternalSymbolResolver::ProgramSymbolResolver::resolveExternalSymbols() {
    unresolvedExternalFunctionIds = getUnresolvedExternalFunctionIds();
    externalSymbolCount = static_cast<int>(unresolvedExternalFunctionIds.size());

    if (unresolvedExternalFunctionIds.empty()) {
        return;
    }

    extLibs = getLibsToSearch();

    if (!extLibs.empty()) {
        for (auto& extLib : extLibs) {
            resolveSymbolsToLibrary(extLib);
        }
    }
}

std::vector<long> ExternalSymbolResolver::ProgramSymbolResolver::getUnresolvedExternalFunctionIds() {
    std::vector<long> symbolIds;
    ExternalManager* externalManager = program->getExternalManager();
    Library* unknownLib = externalManager->getExternalLibrary(Library::UNKNOWN);
    if (unknownLib) {
        SymbolTable* symbolTable = program->getSymbolTable();
        auto symbols = symbolTable->getSymbols(unknownLib);
        for (Symbol* s : symbols) {
            if (s->getSymbolType() == SymbolType::FUNCTION &&
                s->getSource() != SourceType::DEFAULT) {
                symbolIds.push_back(s->getID());
            }
        }
    }
    return symbolIds;
}

std::vector<ExternalSymbolResolver::ProgramSymbolResolver::ExtLibInfo>
    ExternalSymbolResolver::ProgramSymbolResolver::getLibsToSearch() {

    std::vector<ExtLibInfo> result;
    ExternalManager* externalManager = program->getExternalManager();
    for (Library* lib : externalManager->getLibraries()) {
        ExtLibInfo info;
        info.lib = lib;
        result.push_back(info);
    }
    return result;
}

void ExternalSymbolResolver::ProgramSymbolResolver::resolveSymbolsToLibrary(ExtLibInfo& extLib) {
    ExternalManager* externalManager = program->getExternalManager();
    SymbolTable* symbolTable = program->getSymbolTable();

    auto it = unresolvedExternalFunctionIds.begin();
    while (it != unresolvedExternalFunctionIds.end()) {
        Symbol* s = symbolTable->getSymbol(*it);
        if (!s || !s->isExternal() || s->getSymbolType() != SymbolType::FUNCTION) {
            it = unresolvedExternalFunctionIds.erase(it);
            continue;
        }

        ExternalLocation* extLoc = externalManager->getExternalLocation(s);
        if (!extLoc) {
            ++it;
            continue;
        }

        std::string extLocName = extLoc->getLabel();
        if (extLocName.empty()) {
            extLocName = s->getName();
        }

        // If the external location's library name matches this extLib, re-parent it
        if (extLoc->getLibraryName() == extLib.lib->getName() ||
            (extLib.lib->getName() == Library::UNKNOWN)) {
            s->setParentNamespace(extLib.lib);
            it = unresolvedExternalFunctionIds.erase(it);
            extLib.resolvedSymbols.push_back(s->getName());
        }
        else {
            ++it;
        }
    }
}

} // namespace ghidra
