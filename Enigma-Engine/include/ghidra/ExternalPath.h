/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ExternalPath.h
/// \brief External path representation (library::name)
/// Translated from: ghidra.program.model.symbol.ExternalPath
#pragma once

#include <string>
#include <vector>

namespace ghidra {

class ExternalPath {
public:
    static constexpr const char* DELIMITER = "::";

    ExternalPath(std::string library, std::string label);
    ExternalPath(std::vector<std::string> elements);

    const std::string& getLibraryName() const;
    const std::string& getName() const;
    std::vector<std::string> getPathElements() const;
    std::string toString() const;

private:
    std::vector<std::string> elements_;
};

} // namespace ghidra
