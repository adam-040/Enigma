/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IncompatibleLanguageException.h
/// \brief Exception for incompatible language replacement.
/// Translated from: ghidra.program.model.listing.IncompatibleLanguageException
#pragma once

#include <stdexcept>

namespace ghidra {

class IncompatibleLanguageException : public std::runtime_error {
public:
    explicit IncompatibleLanguageException(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace ghidra
