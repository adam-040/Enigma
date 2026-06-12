/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringLayoutEnum.cpp
#include "ghidra/StringLayoutEnum.h"

namespace ghidra {

const char* toString(StringLayoutEnum layout) {
    switch (layout) {
        case StringLayoutEnum::FIXED_LEN: return "fixed length";
        case StringLayoutEnum::CHAR_SEQ: return "char sequence";
        case StringLayoutEnum::NULL_TERMINATED_UNBOUNDED: return "null-terminated & unbounded";
        case StringLayoutEnum::NULL_TERMINATED_BOUNDED: return "null-terminated & bounded";
        case StringLayoutEnum::PASCAL_255: return "pascal255";
        case StringLayoutEnum::PASCAL_64k: return "pascal64k";
    }
    return "";
}

bool isPascalLayout(StringLayoutEnum layout) {
    return layout == StringLayoutEnum::PASCAL_255 || layout == StringLayoutEnum::PASCAL_64k;
}

bool isNullTerminatedLayout(StringLayoutEnum layout) {
    return layout == StringLayoutEnum::NULL_TERMINATED_UNBOUNDED ||
           layout == StringLayoutEnum::NULL_TERMINATED_BOUNDED;
}

bool shouldTrimTrailingNulls(StringLayoutEnum layout) {
    return layout == StringLayoutEnum::NULL_TERMINATED_UNBOUNDED ||
           layout == StringLayoutEnum::NULL_TERMINATED_BOUNDED ||
           layout == StringLayoutEnum::FIXED_LEN;
}

bool isFixedLenLayout(StringLayoutEnum layout) {
    return layout == StringLayoutEnum::FIXED_LEN || layout == StringLayoutEnum::CHAR_SEQ;
}

} // namespace ghidra
