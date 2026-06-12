#pragma once

#include <ghidra/ChangeSet.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>

namespace ghidra {

class RegisterChangeSet : public ChangeSet {
public:
    ~RegisterChangeSet() override = default;

    virtual void addRegisterRange(const Address& addr1, const Address& addr2) = 0;
    virtual AddressSetView* getRegisterAddressSet() = 0;
};

} // namespace ghidra
