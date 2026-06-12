/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DuplicateGroupException.h
/// \brief Exception for duplicate program tree group members.
/// Translated from: ghidra.program.model.listing.DuplicateGroupException
#pragma once

#include <ghidra/UsrException.h>

namespace ghidra {

class DuplicateGroupException : public UsrException {
public:
    DuplicateGroupException() : UsrException("The fragment or module you are adding is already there.") {}
    explicit DuplicateGroupException(const std::string& msg) : UsrException(msg) {}
};

} // namespace ghidra
