#pragma once

#include <ghidra/ChangeSet.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>

namespace ghidra {

class AddressChangeSet : public ChangeSet {
public:
    ~AddressChangeSet() override = default;

    virtual AddressSetView* getAddressSet() = 0;
    virtual void add(AddressSetView* addrSet) = 0;
    virtual void addRange(const Address& addr1, const Address& addr2) = 0;
};

} // namespace ghidra
