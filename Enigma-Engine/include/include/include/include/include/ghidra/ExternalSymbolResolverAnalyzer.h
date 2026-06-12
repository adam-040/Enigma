/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/// \file ExternalSymbolResolverAnalyzer.h
/// \brief Links unresolved external symbols to library namespaces
/// Translated from: ghidra.app.plugin.core.analysis.ExternalSymbolResolverAnalyzer
#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class ExternalSymbolResolverAnalyzer : public AbstractAnalyzer {
public:
    ExternalSymbolResolverAnalyzer();

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
};

} // namespace ghidra
