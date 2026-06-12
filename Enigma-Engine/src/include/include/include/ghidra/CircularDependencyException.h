/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CircularDependencyException.h
/// \brief Exception for program module circular dependencies.
/// Translated from: ghidra.program.model.listing.CircularDependencyException
#pragma once

#include <ghidra/UsrException.h>

namespace ghidra {

class CircularDependencyException : public UsrException {
public:
    CircularDependencyException() : UsrException("Reference is invalid.") {}
    explicit CircularDependencyException(const std::string& msg) : UsrException(msg) {}
};

} // namespace ghidra
