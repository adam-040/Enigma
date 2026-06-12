/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ContextChangeException.h
/// \brief Exception for illegal program context changes.
/// Translated from: ghidra.program.model.listing.ContextChangeException
#pragma once

#include <ghidra/UsrException.h>

namespace ghidra {

class ContextChangeException : public UsrException {
public:
    ContextChangeException() : UsrException() {}
    explicit ContextChangeException(const std::string& msg) : UsrException(msg) {}
};

} // namespace ghidra
