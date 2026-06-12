#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressRangeImpl.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/util/datastruct/RedBlackTree.h>
#include <ghidra/util/datastruct/RedBlackEntry.h>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class Program;

class AddressSetRangeIterator : public AddressRangeIterator {
private:
    std::vector<AddressRange> ranges_;
    std::vector<AddressRange>::iterator current_;
    bool forward_;
public:
    AddressSetRangeIterator(const std::vector<AddressRange>& ranges, const Address& start, bool forward);
    ~AddressSetRangeIterator() override = default;
    bool hasNext() const override;
    const AddressRange& next() override;
};

class AddressSet : public AddressSetView {
private:
    static constexpr double LOGBASE2 = 0.6931471805599453; // ln(2)
    RedBlackTree<Address, Address> rbTree;
    RedBlackEntry<Address, Address>* lastNode = nullptr;
    int64_t addressCount = 0;

    // Internal helpers for Red-Black Tree management
    RedBlackEntry<Address, Address>* createRangeNode(const Address& start, const Address& end);
    void updateRangeEndAddress(RedBlackEntry<Address, Address>* entry, const Address& newEnd);
    RedBlackEntry<Address, Address>* deleteRangeNode(RedBlackEntry<Address, Address>* entry);
    void consumeFollowOnNodes(RedBlackEntry<Address, Address>* node);
    
    enum class RangeCompare {
        RANGE1_COMPLETELY_BEFORE_RANGE2,
        RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2,
        RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END,
        RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2,
        RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2,
        RANGE1_EQUALS_RANGE2,
        RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2,
        RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2,
        RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2,
        RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2,
        RANGE1_COMPLETELY_AFTER_RANGE2
    };

    RangeCompare compareRange(const AddressRange& r1, const AddressRange& r2) const;
    RangeCompare compareRange(const Address& min1, const Address& max1, const Address& min2, const Address& max2) const;

    bool containsInternal(RedBlackEntry<Address, Address>* entry, const Address& start) const;
    
    bool useLinearAlgorithm(const AddressSetView& set) const;
    bool containsLinear(const AddressSetView& addrSet) const;
    bool containsBinary(const AddressSetView& addrSet) const;
    bool intersectsLinear(const AddressSetView& addrSet) const;
    bool intersectsBinary(const AddressSetView& addrSet) const;
    
    AddressSet intersectRange(const Address& start, const Address& end, AddressSet& set) const;
    AddressSet intersectLinear(const AddressSetView& addrSet) const;
    AddressSet intersectBinary(const AddressSetView& addrSet) const;
    AddressSet mergeSets(const AddressSetView& addrSet) const;
    AddressSet deleteSets(const AddressSetView& addrSet) const;
    AddressSet xorSets(const AddressSetView& addrSet) const;

public:
    AddressSet();
    AddressSet(const AddressRange& range);
    AddressSet(const Address& start, const Address& end);
    AddressSet(Program* program, const Address& start, const Address& end);
    AddressSet(const AddressSetView& set);
    AddressSet(const Address& addr);

    void add(const Address& address);
    void add(const AddressRange& range);
    void add(const Address& start, const Address& end);
    void addRange(const Address& start, const Address& end);
    void addRange(Program* program, const Address& start, const Address& end);
    void add(const AddressSetView& addressSet);

    void deleteRange(const AddressRange& range);
    void deleteRange(const Address& start, const Address& end);
    void remove(const Address& start, const Address& end);
    void remove(const AddressSetView& addressSet);
    void clear();

    std::string printRanges() const;
    std::vector<AddressRange> toList() const;

    // AddressSetView overrides
    bool contains(const Address& address) const override;
    bool contains(const Address& start, const Address& end) const override;
    bool contains(const AddressSetView& addrSet) const override;
    bool hasSameAddresses(const AddressSetView& addrSet) const override;
    bool operator==(const AddressSet& other) const;
    bool operator!=(const AddressSet& other) const { return !(*this == other); }
    
    int __hash() const; // Using __hash to avoid conflict with std::hash
    
    bool intersects(const AddressSetView& addrSet) const override;
    bool intersects(const Address& start, const Address& end) const override;
    
    AddressSet intersect(const AddressSetView& addrSet) const override;
    AddressSet intersectRange(const Address& start, const Address& end) const override;
    AddressSet unionSet(const AddressSetView& addrSet) const override; // renamed from union
    AddressSet subtract(const AddressSetView& addrSet) const override;
    AddressSet xorSet(const AddressSetView& addrSet) const override; // renamed from xor

    bool isEmpty() const override;
    Address getMinAddress() const override;
    Address getMaxAddress() const override;
    int getNumAddressRanges() const override;
    int64_t getNumAddresses() const override;

    AddressRangeIterator* getAddressRanges() const override;
    AddressRangeIterator* getAddressRanges(bool forward) const override;
    AddressRangeIterator* getAddressRanges(const Address& start, bool forward) const override;
    
    Address findFirstAddressInCommon(const AddressSetView& set) const override;
    AddressRange getRangeContaining(const Address& address) const override;
    AddressRange getFirstRange() const override;
    AddressRange getLastRange() const override;

    long getAddressCountBefore(const Address& address) const;
    
    static AddressSetView trimStart(const AddressSetView& set, const Address& addr);
    static AddressSetView trimEnd(const AddressSetView& set, const Address& addr);
};

} // namespace ghidra
