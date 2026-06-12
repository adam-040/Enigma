/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CompilerSpec.cpp
/// \brief Compiler specification
#include <ghidra/CompilerSpec.h>

namespace ghidra {

std::vector<std::string> CompilerSpec::getCallingConventionNames() const {
    std::vector<std::string> names;
    for (const auto& pair : callingConventions_) {
        names.push_back(pair.first);
    }
    return names;
}

} // namespace ghidra
