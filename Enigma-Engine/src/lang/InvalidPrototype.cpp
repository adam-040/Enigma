/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InvalidPrototype.cpp
#include "ghidra/InvalidPrototype.h"
#include "ghidra/Language.h"
#include "ghidra/RefType.h"
#include "ghidra/PcodeOp.h"

namespace ghidra {

InvalidPrototype::InvalidPrototype(Language* lang) : language(lang) {}

ParserContext* InvalidPrototype::getParserContext(MemBuffer* /*buf*/, ProcessorContext* /*pc*/) {
    return this;
}

FlowType* InvalidPrototype::getFlowType() {
    return const_cast<FlowType*>(&RefTypes::INVALID);
}

FlowType* InvalidPrototype::getFlowType() const {
    return const_cast<FlowType*>(&RefTypes::INVALID);
}

std::vector<PcodeOp*> InvalidPrototype::getPcodeOps() {
    return std::vector<PcodeOp*>();
}

bool InvalidPrototype::isEquivalent(const InstructionPrototype* other) const {
    return this == other;
}

} // namespace ghidra
