#pragma once

#include <ghidra/AddressRange.h>
#include <ghidra/AddressRangeImpl.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/util/datastruct/RedBlackTree.h>
#include <vector>
#include <memory>

namespace ghidra {

class AddressSet;

class AddressSetView : public std::enable_shared_from_this<AddressSetView> {
public:
    virtual ~AddressSetView() = default;
    virtual bool contains(const Address& addr) const = 0;
    virtual bool contains(const Address& start, const Address& end) const = 0;
    virtual bool contains(const AddressSetView& rangeSet) const = 0;
    virtual bool isEmpty() const = 0;
    virtual Address getMinAddress() const = 0;
    virtual Address getMaxAddress() const = 0;
    virtual int getNumAddressRanges() const = 0;
    virtual int64_t getNumAddresses() const = 0;
    virtual AddressRangeIterator* getAddressRanges() const = 0;
    virtual AddressRangeIterator* getAddressRanges(bool forward) const = 0;
    virtual AddressRangeIterator* getAddressRanges(const Address& start, bool forward) const = 0;
    virtual bool intersects(const AddressSetView& other) const = 0;
    virtual bool intersects(const Address& start, const Address& end) const = 0;
    virtual AddressSet intersect(const AddressSetView& view) const = 0;
    virtual AddressSet intersectRange(const Address& start, const Address& end) const = 0;
    virtual AddressSet unionSet(const AddressSetView& addrSet) const = 0;
    virtual AddressSet subtract(const AddressSetView& addrSet) const = 0;
    virtual AddressSet xorSet(const AddressSetView& addrSet) const = 0;
    virtual bool hasSameAddresses(const AddressSetView& addrSet) const = 0;
    virtual AddressRange getFirstRange() const = 0;
    virtual AddressRange getLastRange() const = 0;
    virtual AddressRange getRangeContaining(const Address& address) const = 0;
    virtual Address findFirstAddressInCommon(const AddressSetView& set) const = 0;

    struct RangeIterator {
        AddressRangeIterator* inner;
        bool hasNext() { return inner && inner->hasNext(); }
        const AddressRange* next() { return &(inner->next()); }
    };
    RangeIterator ranges() const {
        return { getAddressRanges() };
    }
};

} // namespace ghidra
