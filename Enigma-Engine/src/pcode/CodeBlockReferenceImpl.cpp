#include <ghidra/CodeBlockReferenceImpl.h>
#include <ghidra/CodeBlock.h>

namespace ghidra {

CodeBlockReferenceImpl::CodeBlockReferenceImpl(CodeBlock* source, CodeBlock* destination,
                                               FlowType flowType, const Address& reference,
                                               const Address& referent)
    : source_(source), destination_(destination),
      flowType_(flowType), reference_(reference), referent_(referent) {}

Address CodeBlockReferenceImpl::getSourceAddress() const {
    if (source_) return source_->getFirstStartAddress();
    return referent_;
}

Address CodeBlockReferenceImpl::getDestinationAddress() const {
    if (destination_) return destination_->getFirstStartAddress();
    return reference_;
}

std::string CodeBlockReferenceImpl::toString() const {
    return referent_.toString() + " -> " + reference_.toString();
}

} // namespace ghidra
