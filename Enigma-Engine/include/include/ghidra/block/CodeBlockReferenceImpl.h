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

#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/Address.h>

namespace ghidra {

class CodeBlock;
class RefType;

/**
 * CodeBlockReferenceImpl implements the CodeBlockReference interface.
 * Translated from: ghidra.program.model.block.CodeBlockReferenceImpl
 */
class CodeBlockReferenceImpl : public CodeBlockReference {
private:
    CodeBlock* srcBlock_;
    CodeBlock* destBlock_;
    const RefType* flowType_;
    Address refAddr_;
    Address refSrcAddr_;

public:
    CodeBlockReferenceImpl(CodeBlock* srcBlock, CodeBlock* destBlock,
                           const RefType* flowType, const Address& refAddr,
                           const Address& refSrcAddr);

    ~CodeBlockReferenceImpl() override = default;

    CodeBlock* getSourceBlock() const override { return srcBlock_; }
    CodeBlock* getDestinationBlock() const override { return destBlock_; }

    const RefType* getFlowType() const override { return flowType_; }

    Address getReference() const override { return refAddr_; }
    Address getReferent() const override { return refSrcAddr_; }

    Address getSourceAddress() const override { return refSrcAddr_; }
    Address getDestinationAddress() const override { return refAddr_; }
};

} // namespace ghidra
