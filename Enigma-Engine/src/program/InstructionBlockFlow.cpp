/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InstructionBlockFlow.cpp
/// \brief Flow entry within an InstructionBlock
#include <ghidra/InstructionBlockFlow.h>
#include <sstream>

namespace ghidra {

InstructionBlockFlow::InstructionBlockFlow(const Address& address, const Address& flowFrom, Type type)
    : address_(address), flowFrom_(flowFrom), type_(type) {}

bool InstructionBlockFlow::operator==(const InstructionBlockFlow& other) const {
    return type_ == other.type_ && address_ == other.address_ && flowFrom_ == other.flowFrom_;
}

bool InstructionBlockFlow::operator<(const InstructionBlockFlow& other) const {
    if (address_ < other.address_) return true;
    if (other.address_ < address_) return false;
    if (flowFrom_ < other.flowFrom_) return true;
    if (other.flowFrom_ < flowFrom_) return false;
    return static_cast<int>(type_) < static_cast<int>(other.type_);
}

std::string InstructionBlockFlow::toString() const {
    std::ostringstream ss;
    switch (type_) {
        case Type::PRIORITY: ss << "PRIORITY"; break;
        case Type::BRANCH: ss << "BRANCH"; break;
        case Type::CALL_FALLTHROUGH: ss << "CALL_FALLTHROUGH"; break;
        case Type::CALL: ss << "CALL"; break;
    }
    ss << " " << flowFrom_.toString() << "->" << address_.toString();
    return ss.str();
}

} // namespace ghidra
