/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GenericCallingConvention.h
/// \brief Generic calling convention enumeration.
#pragma once

#include <string>

namespace ghidra {

/**
 * GenericCallingConvention identifies the generic calling convention
 * associated with a specific function definition.
 * Translated from: ghidra.program.model.data.GenericCallingConvention
 */
class GenericCallingConvention {
public:
    static inline const std::string unknown = "unknown";
    static inline const std::string stdcall = "__stdcall";
    static inline const std::string cdecl_cc = "__cdecl";
    static inline const std::string fastcall = "__fastcall";
    static inline const std::string thiscall = "__thiscall";
    static inline const std::string vectorcall = "__vectorcall";
};

} // namespace ghidra
