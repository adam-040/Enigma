/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file GhidraLanguagePropertyKeys.cpp
#include "ghidra/GhidraLanguagePropertyKeys.h"

namespace ghidra {

const std::string GhidraLanguagePropertyKeys::MAXIMUM_INSTRUCTION_LENGTH = "maximumInstructionLength";
const std::string GhidraLanguagePropertyKeys::CUSTOM_DISASSEMBLER_CLASS = "customDisassemblerClass";
const std::string GhidraLanguagePropertyKeys::ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS = "allowOffcutReferencesToFunctionStarts";
const std::string GhidraLanguagePropertyKeys::USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES = "useOperandReferenceAnalyzerSwitchTables";
const std::string GhidraLanguagePropertyKeys::IS_TMS320_FAMILY = "isTMS320Family";
const std::string GhidraLanguagePropertyKeys::PARALLEL_INSTRUCTION_HELPER_CLASS = "parallelInstructionHelperClass";
const std::string GhidraLanguagePropertyKeys::ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE = "addressesDoNotAppearDirectlyInCode";
const std::string GhidraLanguagePropertyKeys::USE_NEW_FUNCTION_STACK_ANALYSIS = "useNewFunctionStackAnalysis";
const std::string GhidraLanguagePropertyKeys::EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS = "emulateInstructionStateModifierClass";
const std::string GhidraLanguagePropertyKeys::USEROP_LIBS = "useropLibs";
const std::string GhidraLanguagePropertyKeys::PCODE_INJECT_LIBRARY_CLASS = "pcodeInjectLibraryClass";
const std::string GhidraLanguagePropertyKeys::ENABLE_SHARED_RETURN_ANALYSIS = "enableSharedReturnAnalysis";
const std::string GhidraLanguagePropertyKeys::ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY = "enableContiguousFunctionsOnly";
const std::string GhidraLanguagePropertyKeys::ENABLE_NO_RETURN_ANALYSIS = "enableNoReturnAnalysis";
const std::string GhidraLanguagePropertyKeys::RESET_CONTEXT_ON_UPGRADE = "resetContextOnUpgrade";
const std::string GhidraLanguagePropertyKeys::MINIMUM_DATA_IMAGE_BASE = "minimumDataImageBase";

} // namespace ghidra
