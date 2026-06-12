/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramChangeRecord.cpp
/// \brief Event data for a change in a Program.
#include "ghidra/ProgramChangeRecord.h"
#include <sstream>

namespace ghidra {

ProgramChangeRecord::ProgramChangeRecord(ProgramEvent eventType,
                                         const Address& start, const Address& end, void* affected,
                                         const std::string& oldValue, const std::string& newValue)
    : eventType_(eventType), start_(start), end_(end),
      affected_(affected), oldValue_(oldValue), newValue_(newValue) {}

std::string ProgramChangeRecord::toString() const {
    std::ostringstream os;
    os << "ProgramChangeRecord(event=" << static_cast<int>(eventType_);
    if (affected_ != nullptr) os << ", affected=" << affected_;
    if (!oldValue_.empty()) os << ", old=" << oldValue_;
    if (!newValue_.empty()) os << ", new=" << newValue_;
    os << ")";
    return os.str();
}

} // namespace ghidra
