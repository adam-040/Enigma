/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/Address.h>
#include <ghidra/RefType.h>

namespace ghidra {

class CodeBlock;

class CodeBlockReference {
public:
    virtual ~CodeBlockReference() = default;
    virtual Address getSourceAddress() const = 0;
    virtual Address getDestinationAddress() const = 0;
    virtual FlowType getFlowType() const = 0;
    virtual Address getReference() const = 0;
    virtual Address getReferent() const = 0;
    virtual CodeBlock* getDestinationBlock() const = 0;
    virtual CodeBlock* getSourceBlock() const = 0;
};

} // namespace ghidra
