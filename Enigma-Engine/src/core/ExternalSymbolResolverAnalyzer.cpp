/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/// \file ExternalSymbolResolverAnalyzer.cpp
/// \brief Links unresolved external symbols to library namespaces
#include <ghidra/ExternalSymbolResolverAnalyzer.h>
#include <ghidra/ExternalSymbolResolver.h>
#include <ghidra/Program.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

ExternalSymbolResolverAnalyzer::ExternalSymbolResolverAnalyzer()
    : AbstractAnalyzer("External Symbol Resolver",
                       "Links unresolved external symbols to the first symbol found in the program's required libraries list.",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis();
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.before().before().before().before());
}

bool ExternalSymbolResolverAnalyzer::canAnalyze(Program* program) const {
    // Simplified: skip project check; check if format hints at external symbols
    std::string format = program->getExecutableFormat();
    if (format.empty()) return true;
    // Only run on PE, ELF, or Mach-O formats
    if (format.find("PE") != std::string::npos) return true;
    if (format.find("ELF") != std::string::npos) return true;
    if (format.find("Mach-O") != std::string::npos) return true;
    return true; // default to true for unknown formats
}

bool ExternalSymbolResolverAnalyzer::added(Program* program, const AddressSetView& set,
                                           TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    ExternalSymbolResolver esr(program);
    esr.addProgramToFixup(program);
    esr.fixUnresolvedExternalSymbols();

    esr.logInfo([&](const std::string& msg) {
        log.append(msg);
    }, false);

    if (esr.hasProblemLibraries()) {
        esr.logInfo([&](const std::string& msg) {
            log.append(msg);
        }, true);
    }

    return true;
}

} // namespace ghidra
