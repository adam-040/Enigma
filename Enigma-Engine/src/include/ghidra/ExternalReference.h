/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalReference.h
/// \brief Interface for references to external locations
/// Translated from: ghidra.program.model.symbol.ExternalReference
#pragma once

#include <ghidra/Reference.h>
#include <string>

namespace ghidra {

class ExternalLocation;

class ExternalReference : public virtual Reference {
public:
    virtual ExternalLocation* getExternalLocation() const = 0;
    virtual std::string getLibraryName() const = 0;
    virtual std::string getLabel() const = 0;
};

} // namespace ghidra
