/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VariableSizeException.h
/// \brief Exception for variable data-type exceeding storage constraints.
/// Translated from: ghidra.program.model.listing.VariableSizeException
#pragma once

#include <ghidra/InvalidInputException.h>

namespace ghidra {

class VariableSizeException : public InvalidInputException {
public:
    explicit VariableSizeException(const std::string& msg)
        : InvalidInputException(msg), canForce_(false) {}
    VariableSizeException(const std::string& msg, bool canForce)
        : InvalidInputException(msg), canForce_(canForce) {}

    bool canForce() const { return canForce_; }

private:
    bool canForce_;
};

} // namespace ghidra
