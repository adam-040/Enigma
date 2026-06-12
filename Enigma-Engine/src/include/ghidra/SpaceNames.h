/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SpaceNames.h
/// \brief Reserved AddressSpace names across architectures and associated attributes
/// Translated from: ghidra.program.model.lang.SpaceNames
#pragma once

#include <string>

namespace ghidra {

struct SpaceNames {
    static inline const std::string CONSTANT_SPACE_NAME = "const";
    static inline const std::string UNIQUE_SPACE_NAME = "unique";
    static inline const std::string STACK_SPACE_NAME = "stack";
    static inline const std::string JOIN_SPACE_NAME = "join";
    static inline const std::string OTHER_SPACE_NAME = "OTHER";
    static inline const std::string IOP_SPACE_NAME = "iop";
    static inline const std::string FSPEC_SPACE_NAME = "fspec";

    static constexpr int CONSTANT_SPACE_INDEX = 0;
    static constexpr int OTHER_SPACE_INDEX = 1;
    static constexpr int UNIQUE_SPACE_SIZE = 4;
};

} // namespace ghidra
