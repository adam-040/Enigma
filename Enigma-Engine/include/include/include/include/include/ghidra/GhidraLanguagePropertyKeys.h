/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GhidraLanguagePropertyKeys.h
/// \brief Standard property keys recognized by the Ghidra language loader
/// Translated from: ghidra.program.model.lang.GhidraLanguagePropertyKeys
#pragma once

#include <string>

namespace ghidra {

class GhidraLanguagePropertyKeys {
public:
    static const std::string MAXIMUM_INSTRUCTION_LENGTH;
    static const std::string CUSTOM_DISASSEMBLER_CLASS;
    static const std::string ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS;
    static const std::string USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES;
    static const std::string IS_TMS320_FAMILY;
    static const std::string PARALLEL_INSTRUCTION_HELPER_CLASS;
    static const std::string ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE;
    static const std::string USE_NEW_FUNCTION_STACK_ANALYSIS;
    static const std::string EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS;
    static const std::string USEROP_LIBS;
    static const std::string PCODE_INJECT_LIBRARY_CLASS;
    static const std::string ENABLE_SHARED_RETURN_ANALYSIS;
    static const std::string ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY;
    static const std::string ENABLE_NO_RETURN_ANALYSIS;
    static const std::string RESET_CONTEXT_ON_UPGRADE;
    static const std::string MINIMUM_DATA_IMAGE_BASE;
};

} // namespace ghidra
