/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PackingType.h
/// \brief Packing type for composite data types.
#pragma once

namespace ghidra {

/**
 * Specifies the pack setting for a composite data type.
 * Translated from: ghidra.program.model.data.PackingType
 */
enum class PackingType {
    DISABLED,
    DEFAULT,
    EXPLICIT
};

} // namespace ghidra
