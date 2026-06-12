/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MemReferenceImpl.cpp
/// \brief Concrete memory reference implementation
#include <ghidra/MemReferenceImpl.h>
#include <ghidra/RefType.h>
#include <ghidra/AddressSpace.h>
#include <sstream>

namespace ghidra {

MemReferenceImpl::MemReferenceImpl(Address fromAddr, Address toAddr, const RefType* type,
                                   SourceType source, int operandIndex,
                                   bool isPrimary, long id)
    : fromAddr_(fromAddr), toAddr_(toAddr), type_(type),
      operandIndex_(operandIndex), source_(source),
      isPrimary_(isPrimary), id_(id) {}

std::string MemReferenceImpl::toString() const {
    std::ostringstream ss;
    ss << fromAddr_.toString() << " -> " << toAddr_.toString();
    if (type_) ss << " (" << type_->toString() << ")";
    return ss.str();
}

bool MemReferenceImpl::operator==(const Reference& other) const {
    if (auto* memRef = dynamic_cast<const MemReferenceImpl*>(&other)) {
        return fromAddr_ == memRef->fromAddr_ &&
               toAddr_ == memRef->toAddr_ &&
               operandIndex_ == memRef->operandIndex_ &&
               type_ == memRef->type_ &&
               isPrimary_ == memRef->isPrimary_ &&
               source_ == memRef->source_;
    }
    return false;
}

bool MemReferenceImpl::operator!=(const Reference& other) const {
    return !(*this == other);
}

} // namespace ghidra
