/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeException.h
/// \brief Exception thrown on problems with Pcode.
/// Translated from: ghidra.program.model.pcode.PcodeException
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {
namespace pcode {

class PcodeException : public std::runtime_error {
public:
    explicit PcodeException(const std::string& msg) : std::runtime_error("Pcode: " + msg) {}
    PcodeException(const std::string& msg, const std::exception& cause)
        : std::runtime_error(std::string("Pcode: ") + msg + " (caused by " + cause.what() + ")") {}
};

}  // namespace pcode
}  // namespace ghidra
