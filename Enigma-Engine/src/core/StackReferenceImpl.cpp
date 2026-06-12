#include <ghidra/StackReferenceImpl.h>
#include <ghidra/RefType.h>
#include <sstream>

namespace ghidra {

StackReferenceImpl::StackReferenceImpl(Address fromAddr, int stackOffset, const RefType* type,
                                       SourceType source, int operandIndex, bool isPrimary, long id)
    : fromAddr_(fromAddr), stackOffset_(stackOffset), type_(type),
      operandIndex_(operandIndex), source_(source),
      isPrimary_(isPrimary), id_(id) {}

Address StackReferenceImpl::getToAddress() const {
    return Address(const_cast<AddressSpace*>(fromAddr_.getAddressSpace()), stackOffset_);
}

bool StackReferenceImpl::operator==(const Reference& other) const {
    if (id_ >= 0 && other.getID() >= 0)
        return id_ == other.getID();
    return fromAddr_ == other.getFromAddress() &&
           getToAddress() == other.getToAddress() &&
           operandIndex_ == other.getOperandIndex();
}

bool StackReferenceImpl::operator!=(const Reference& other) const {
    return !(*this == other);
}

std::string StackReferenceImpl::toString() const {
    std::ostringstream oss;
    oss << "StackRef[from=" << fromAddr_.toString()
        << ", stackOffset=" << stackOffset_
        << ", type=" << (type_ ? type_->getName() : "null")
        << "]";
    return oss.str();
}

} // namespace ghidra
