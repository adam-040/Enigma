/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/block/CodeBlock.h>
#include <ghidra/RefType.h>

namespace ghidra {

CodeBlockReferenceImpl::CodeBlockReferenceImpl(CodeBlock* srcBlock, CodeBlock* destBlock,
                                               const RefType* flowType, const Address& refAddr,
                                               const Address& refSrcAddr)
    : srcBlock_(srcBlock), destBlock_(destBlock), flowType_(flowType),
      refAddr_(refAddr), refSrcAddr_(refSrcAddr) {
}

} // namespace ghidra
