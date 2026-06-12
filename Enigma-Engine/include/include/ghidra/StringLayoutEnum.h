/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringLayoutEnum.h
/// \brief Controls string termination layout
/// Translated from: ghidra.program.model.data.StringLayoutEnum
#pragma once

#include <string>

namespace ghidra {

/**
 * Controls a string's termination layout (fixed-length, char sequence,
 * null-terminated bounded/unbounded, pascal255/64k).
 *
 * Translated from: ghidra.program.model.data.StringLayoutEnum
 */
enum class StringLayoutEnum {
    FIXED_LEN,
    CHAR_SEQ,
    NULL_TERMINATED_UNBOUNDED,
    NULL_TERMINATED_BOUNDED,
    PASCAL_255,
    PASCAL_64k
};

const char* toString(StringLayoutEnum layout);
bool isPascalLayout(StringLayoutEnum layout);
bool isNullTerminatedLayout(StringLayoutEnum layout);
bool shouldTrimTrailingNulls(StringLayoutEnum layout);
bool isFixedLenLayout(StringLayoutEnum layout);

} // namespace ghidra
