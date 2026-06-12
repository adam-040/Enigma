#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

class AddressSetCollection {
public:
    virtual ~AddressSetCollection() = default;

    virtual bool intersects(const AddressSetView& addrSet) = 0;
    virtual bool intersects(const Address& start, const Address& end) = 0;
    virtual bool contains(const Address& address) = 0;
    virtual bool hasFewerRangesThan(int rangeThreshold) = 0;
    virtual AddressSet getCombinedAddressSet() = 0;
    virtual Address findFirstAddressInCommon(const AddressSetView& set) = 0;
    virtual bool isEmpty() = 0;
    virtual Address getMinAddress() = 0;
    virtual Address getMaxAddress() = 0;
};

} // namespace ghidra
