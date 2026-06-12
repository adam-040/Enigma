#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressSetView.h>
#include <vector>

namespace ghidra {

class AbstractAddressSetView : public AddressSetView {
public:
    virtual ~AbstractAddressSetView() = default;

    bool isEmpty() const override;
    bool contains(const Address& start, const Address& end) const override;
    bool contains(const AddressSetView& rangeSet) const override;
    Address getMinAddress() const override;
    Address getMaxAddress() const override;
    int getNumAddressRanges() const override;

    AddressRangeIterator* getAddressRanges() const override;
    AddressRangeIterator* getAddressRanges(bool forward) const override;
    AddressRangeIterator* getAddressRanges(const Address& start, bool forward) const override;

    int64_t getNumAddresses() const override;

    bool hasSameAddresses(const AddressSetView& view) const override;
    AddressRange getFirstRange() const override;
    AddressRange getLastRange() const override;
    bool intersects(const AddressSetView& addrSet) const override;
    bool intersects(const Address& start, const Address& end) const override;
    AddressSet intersect(const AddressSetView& view) const override;
    AddressSet intersectRange(const Address& start, const Address& end) const override;
    AddressSet unionSet(const AddressSetView& addrSet) const override;
    AddressSet subtract(const AddressSetView& addrSet) const override;
    AddressSet xorSet(const AddressSetView& addrSet) const override;
    Address findFirstAddressInCommon(const AddressSetView& set) const override;
    AddressRange getRangeContaining(const Address& address) const override;

protected:
    virtual std::vector<AddressRange> getRanges() const = 0;
};

} // namespace ghidra
