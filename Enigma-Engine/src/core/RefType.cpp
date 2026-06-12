/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RefType.cpp
/// \brief Reference types and FlowTypes implementation
#include <ghidra/RefType.h>

namespace ghidra {

std::string RefType::getDisplayString() const {
    if (isRead() && isWrite()) return "RW";
    if (isRead()) return "Read";
    if (isWrite()) return "Write";
    if (isData()) return "Data";
    if (isCall()) return "Call";
    if (isJump()) return isConditional() ? "Branch" : "Jump";
    return "Unknown";
}

bool RefType::isFallthrough() const { return type_ == __FALL_THROUGH; }

} // namespace ghidra
