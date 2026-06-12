/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AlignmentType.h
/// \brief Alignment type for composite data types.
#pragma once

namespace ghidra {

/**
 * Specifies the type of alignment for a composite data type.
 * Translated from: ghidra.program.model.data.AlignmentType
 */
enum class AlignmentType {
    DEFAULT,
    MACHINE,
    EXPLICIT
};

} // namespace ghidra
