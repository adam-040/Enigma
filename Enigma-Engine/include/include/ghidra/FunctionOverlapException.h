/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionOverlapException.h
/// \brief Exception for overlapping functions.
/// Translated from: ghidra.program.model.listing.FunctionOverlapException
#pragma once

#include <ghidra/UsrException.h>

namespace ghidra {

class FunctionOverlapException : public UsrException {
public:
    FunctionOverlapException() : UsrException("Function overlaps another.") {}
    explicit FunctionOverlapException(const std::string& msg) : UsrException(msg) {}
};

} // namespace ghidra
