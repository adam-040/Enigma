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

#include <ghidra/pcode/CodeBlockReference.h>
#include <ghidra/Address.h>

namespace ghidra::pcode {

class CodeBlock;

class CodeBlockReferenceImpl : public CodeBlockReference {
public:
    CodeBlockReferenceImpl(CodeBlock* source, CodeBlock* destination, FlowType flowType,
                           const Address& reference, const Address& referent);

    Address getSourceAddress() const override;
    Address getDestinationAddress() const override;
    FlowType getFlowType() const override { return flowType_; }
    Address getReference() const override { return reference_; }
    Address getReferent() const override { return referent_; }
    CodeBlock* getDestinationBlock() const override { return destination_; }
    CodeBlock* getSourceBlock() const override { return source_; }

    std::string toString() const;

private:
    CodeBlock* source_;
    CodeBlock* destination_;
    FlowType flowType_;
    Address reference_;
    Address referent_;
};

} // namespace ghidra::pcode
