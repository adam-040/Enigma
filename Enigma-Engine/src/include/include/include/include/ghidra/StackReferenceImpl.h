#pragma once

#include <ghidra/StackReference.h>
#include <ghidra/Address.h>
#include <ghidra/SourceType.h>
#include <string>

namespace ghidra {

class RefType;

class StackReferenceImpl : public StackReference {
public:
    StackReferenceImpl() = default;
    StackReferenceImpl(Address fromAddr, int stackOffset, const RefType* type,
                       SourceType source = SourceType::DEFAULT,
                       int operandIndex = NOOperandIndex,
                       bool isPrimary = true,
                       long id = -1);

    Address getFromAddress() const override { return fromAddr_; }
    Address getToAddress() const override;
    bool isPrimary() const override { return isPrimary_; }
    long getSymbolID() const override { return symbolID_; }
    const RefType* getReferenceType() const override { return type_; }
    int getOperandIndex() const override { return operandIndex_; }
    bool isMnemonicReference() const override { return !isOperandReference(); }
    bool isOperandReference() const override { return operandIndex_ >= 0; }
    bool isStackReference() const override { return true; }
    bool isExternalReference() const override { return false; }
    bool isEntryPointReference() const override { return false; }
    bool isMemoryReference() const override { return false; }
    bool isRegisterReference() const override { return false; }
    bool isOffsetReference() const override { return false; }
    bool isShiftedReference() const override { return false; }
    SourceType getSource() const override { return source_; }
    long getID() const override { return id_; }

    int getStackOffset() const override { return stackOffset_; }

    std::string toString() const override;

    using Reference::operator==;
    using Reference::operator!=;
    bool operator==(const Reference& other) const override;
    bool operator!=(const Reference& other) const override;

    void setSource(SourceType source) { source_ = source; }

private:
    Address fromAddr_;
    int stackOffset_ = 0;
    const RefType* type_ = nullptr;
    int operandIndex_ = NOOperandIndex;
    SourceType source_ = SourceType::DEFAULT;
    long symbolID_ = -1;
    bool isPrimary_ = true;
    long id_ = -1;
};

} // namespace ghidra
