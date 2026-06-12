/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CommentType.h
/// \brief Types of comments on a CodeUnit.
/// Translated from: ghidra.program.model.listing.CommentType
#pragma once

#include <stdexcept>
#include <string>

namespace ghidra {

enum class CommentType : int {
    EOL,         ///< end-of-line comment
    PRE,         ///< comment before the code unit
    POST,        ///< comment after the code unit
    PLATE,       ///< decorated border comment before code unit
    REPEATABLE   ///< comment shown at locations referencing this address
};

inline std::string commentTypeToString(CommentType t) {
    switch (t) {
    case CommentType::EOL: return "EOL";
    case CommentType::PRE: return "PRE";
    case CommentType::POST: return "POST";
    case CommentType::PLATE: return "PLATE";
    case CommentType::REPEATABLE: return "REPEATABLE";
    }
    return "";
}

inline CommentType commentTypeValueOf(int ordinal) {
    switch (ordinal) {
    case 0: return CommentType::EOL;
    case 1: return CommentType::PRE;
    case 2: return CommentType::POST;
    case 3: return CommentType::PLATE;
    case 4: return CommentType::REPEATABLE;
    default: throw std::invalid_argument("Invalid comment type ordinal: " + std::to_string(ordinal));
    }
}

} // namespace ghidra
