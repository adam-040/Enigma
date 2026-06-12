/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/// \file Library.h
/// \brief Library namespace for external symbols
/// Translated from: ghidra.program.model.symbol.Library
#pragma once

#include <ghidra/Namespace.h>
#include <string>

namespace ghidra {

class Symbol;

class Library : public Namespace {
public:
    static constexpr const char* UNKNOWN = "<EXTERNAL>";

    Library() = default;
    Library(const std::string& name, Namespace* parent = nullptr, long id = -1)
        : Namespace(name, parent, id) {}

    static Library* getContainingLibrary(Symbol* symbol);

    const std::string& getAssociatedProgramPath() const { return associatedPath_; }
    void setAssociatedProgramPath(const std::string& path) { associatedPath_ = path; }

private:
    std::string associatedPath_;
};

} // namespace ghidra
