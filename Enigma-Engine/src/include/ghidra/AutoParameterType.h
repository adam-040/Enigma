/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AutoParameterType.h
/// \brief Auto-parameter types (this, return storage pointer, etc.)
/// Translated from: ghidra.program.model.listing.AutoParameterType
#pragma once

#include <string>

namespace ghidra {

enum class AutoParameterType : int {
    THIS,                    ///< object pointer (__thiscall hidden param)
    RETURN_STORAGE_PTR       ///< caller-allocated return storage hidden param
};

inline std::string getAutoParameterTypeDisplayName(AutoParameterType t) {
    switch (t) {
    case AutoParameterType::THIS: return "this";
    case AutoParameterType::RETURN_STORAGE_PTR: return "__return_storage_ptr__";
    }
    return "";
}

inline std::string getDisplayName(AutoParameterType t) {
    return getAutoParameterTypeDisplayName(t);
}

} // namespace ghidra
