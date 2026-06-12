#include "ghidra/AddressSet.h"
#include "ghidra/AddressRangeImpl.h"
#include <cmath>
#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace ghidra {

AddressSet::AddressSet() = default;

AddressSet::AddressSet(const AddressRange& range) {
    add(range);
}

AddressSet::AddressSet(const Address& start, const Address& end) {
    addRange(start, end);
}

AddressSet::AddressSet(Program* program, const Address& start, const Address& end) {
    addRange(start, end);
}

AddressSet::AddressSet(const AddressSetView& set) {
    add(set);
}

AddressSet::AddressSet(const Address& addr) : AddressSet(addr, addr) {}

void AddressSet::add(const Address& address) {
    addRange(address, address);
}

void AddressSet::add(const AddressRange& range) {
    add(range.getMinAddress(), range.getMaxAddress());
}

void AddressSet::add(const Address& start, const Address& end) {
    AddressRange::checkValidRange(start, end);

    if (lastNode != nullptr && !lastNode->isDisposed()) {
        Address value = lastNode->getValue();
        if (containsInternal(lastNode, start) || value.isSuccessor(start)) {
            if (end.compareTo(value) > 0) {
                updateRangeEndAddress(lastNode, end);
                consumeFollowOnNodes(lastNode);
            }
            return;
        }
    }

    if (rbTree.isEmpty()) {
        lastNode = createRangeNode(start, end);
        return;
    }

    if (start.compareTo(rbTree.getLast()->getKey()) > 0) {
        RedBlackEntry<Address, Address>* last = rbTree.getLast();
        Address value = last->getValue();
        if (containsInternal(last, start) || value.isSuccessor(start)) {
            if (end.compareTo(value) > 0) {
                updateRangeEndAddress(last, end);
            }
        } else {
            lastNode = createRangeNode(start, end);
        }
        return;
    }

    lastNode = rbTree.getEntryLessThanEqual(start);
    if (lastNode == nullptr) {
        lastNode = createRangeNode(start, end);
        consumeFollowOnNodes(lastNode);
        return;
    }

    Address nodeEnd = lastNode->getValue();
    if (nodeEnd.compareTo(start) >= 0 || nodeEnd.isSuccessor(start)) {
        if (end.compareTo(nodeEnd) > 0) {
            updateRangeEndAddress(lastNode, end);
            consumeFollowOnNodes(lastNode);
        }
        return;
    }

    lastNode = createRangeNode(start, end);
    consumeFollowOnNodes(lastNode);
}

void AddressSet::addRange(const Address& start, const Address& end) {
    add(start, end);
}

void AddressSet::addRange(Program* program, const Address& start, const Address& end) {
    if (start.getAddressSpace() == end.getAddressSpace()) {
        addRange(start, end);
        return;
    }
    throw std::runtime_error("Addresses in different spaces");
}

void AddressSet::add(const AddressSetView& addressSet) {
    if (addressSet.isEmpty()) return;

    AddressRangeIterator* it = addressSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        addRange(range.getMinAddress(), range.getMaxAddress());
    }
    delete it;
}

void AddressSet::deleteRange(const AddressRange& range) {
    remove(range.getMinAddress(), range.getMaxAddress());
}

void AddressSet::deleteRange(const Address& start, const Address& end) {
    remove(start, end);
}

void AddressSet::remove(const Address& start, const Address& end) {
    if (start.compareTo(end) > 0) {
        throw std::invalid_argument("Start address is greater than end address");
    }
    RedBlackEntry<Address, Address>* entry = rbTree.getEntryLessThanEqual(start);
    if (entry == nullptr) {
        entry = rbTree.getFirst();
    } else if (entry->getValue().compareTo(start) < 0) {
        entry = entry->getSuccessor();
    }

    while (entry != nullptr) {
        Address minRange = entry->getKey();
        Address maxRange = entry->getValue();
        switch (compareRange(start, end, minRange, maxRange)) {
            case RangeCompare::RANGE1_COMPLETELY_AFTER_RANGE2:
                entry = entry->getSuccessor();
                break;
            case RangeCompare::RANGE1_COMPLETELY_BEFORE_RANGE2:
                return;
            case RangeCompare::RANGE1_EQUALS_RANGE2:
                deleteRangeNode(entry);
                return;
            case RangeCompare::RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2:
            case RangeCompare::RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2:
            case RangeCompare::RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END:
                entry = deleteRangeNode(entry);
                break;
            case RangeCompare::RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2:
            case RangeCompare::RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2:
                deleteRangeNode(entry);
                createRangeNode(end.next(), maxRange);
                return;
            case RangeCompare::RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2:
            case RangeCompare::RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2:
                updateRangeEndAddress(entry, start.previous());
                entry = entry->getSuccessor();
                break;
            case RangeCompare::RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2:
                updateRangeEndAddress(entry, start.previous());
                createRangeNode(end.next(), maxRange);
                return;
        }
    }
}

void AddressSet::remove(const AddressSetView& addressSet) {
    if (addressSet.isEmpty()) return;
    if (isEmpty()) return;

    AddressRangeIterator* it = addressSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        deleteRange(range);
    }
    delete it;
}

void AddressSet::clear() {
    rbTree.removeAll();
    lastNode = nullptr;
    addressCount = 0;
}

std::string AddressSet::printRanges() const {
    std::stringstream ss;
    ss << "[";
    auto ranges = toList();
    for (size_t i = 0; i < ranges.size(); i++) {
        if (i > 0) ss << " ";
        ss << ranges[i].toString();
    }
    ss << "]";
    return ss.str();
}

std::vector<AddressRange> AddressSet::toList() const {
    std::vector<AddressRange> list;
    if (rbTree.isEmpty()) return list;
    RedBlackEntry<Address, Address>* entry = rbTree.getFirst();
    while (entry) {
        list.emplace_back(entry->getKey(), entry->getValue());
        entry = entry->getSuccessor();
    }
    return list;
}

bool AddressSet::contains(const Address& address) const {
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(address);
    if (entry == nullptr) return false;
    return address.compareTo(entry->getValue()) <= 0;
}

bool AddressSet::contains(const Address& start, const Address& end) const {
    AddressRange::checkValidRange(start, end);
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(start);
    if (entry == nullptr) return false;
    return end.compareTo(entry->getValue()) <= 0;
}

bool AddressSet::contains(const AddressSetView& addrSet) const {
    if (addrSet.isEmpty()) return true;
    if (isEmpty()) return false;

    Address thisMinAddr = getMinAddress();
    Address thatMinAddr = addrSet.getMinAddress();
    if (thisMinAddr.compareTo(thatMinAddr) > 0) return false;

    Address thisMaxAddr = getMaxAddress();
    Address thatMaxAddr = addrSet.getMaxAddress();
    if (thisMaxAddr.compareTo(thatMaxAddr) < 0) return false;

    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        if (!contains(range.getMinAddress(), range.getMaxAddress())) {
            delete it;
            return false;
        }
    }
    delete it;
    return true;
}

bool AddressSet::hasSameAddresses(const AddressSetView& addrSet) const {
    if (addrSet.isEmpty() && isEmpty()) return true;
    if (addrSet.isEmpty() || isEmpty()) return false;
    if (addrSet.getNumAddresses() != getNumAddresses()) return false;
    if (addrSet.getNumAddressRanges() != getNumAddressRanges()) return false;

    auto myRanges = toList();
    AddressRangeIterator* otherRanges = addrSet.getAddressRanges();
    size_t idx = 0;
    while (otherRanges && otherRanges->hasNext() && idx < myRanges.size()) {
        if (!otherRanges->next().equals(myRanges[idx])) {
            delete otherRanges;
            return false;
        }
        idx++;
    }
    delete otherRanges;
    return true;
}

bool AddressSet::intersects(const AddressSetView& addrSet) const {
    if (isEmpty() || addrSet.isEmpty()) return false;

    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        if (intersects(range.getMinAddress(), range.getMaxAddress())) {
            delete it;
            return true;
        }
    }
    delete it;
    return false;
}

bool AddressSet::intersects(const Address& start, const Address& end) const {
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(end);
    if (entry == nullptr) return false;
    return start.compareTo(entry->getValue()) <= 0;
}

AddressSet AddressSet::intersect(const AddressSetView& addrSet) const {
    if (addrSet.isEmpty() || isEmpty()) return AddressSet();

    AddressSet result;
    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        AddressSet intersection = intersectRange(range.getMinAddress(), range.getMaxAddress());
        if (!intersection.isEmpty()) {
            result.add(intersection);
        }
    }
    delete it;
    return result;
}

AddressSet AddressSet::intersectRange(const Address& start, const Address& end) const {
    AddressSet result;
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(end);
    if (entry == nullptr) return result;

    while (entry) {
        Address minR = entry->getKey();
        Address maxR = entry->getValue();
        if (minR.compareTo(end) > 0) break;
        Address iMin = (minR.compareTo(start) > 0) ? minR : start;
        Address iMax = (maxR.compareTo(end) < 0) ? maxR : end;
        if (iMin.compareTo(iMax) <= 0) {
            result.addRange(iMin, iMax);
        }
        entry = entry->getSuccessor();
    }
    return result;
}

AddressSet AddressSet::unionSet(const AddressSetView& addrSet) const {
    AddressSet result(*this);
    result.add(addrSet);
    return result;
}

AddressSet AddressSet::subtract(const AddressSetView& addrSet) const {
    AddressSet result(*this);
    result.remove(addrSet);
    return result;
}

AddressSet AddressSet::xorSet(const AddressSetView& addrSet) const {
    AddressSet unionSet;
    unionSet.add(*this);
    unionSet.add(addrSet);
    AddressSet intersection = intersect(addrSet);
    unionSet.remove(intersection);
    return unionSet;
}

bool AddressSet::isEmpty() const { return rbTree.isEmpty(); }

Address AddressSet::getMinAddress() const {
    if (rbTree.isEmpty()) return Address();
    return rbTree.getFirst()->getKey();
}

Address AddressSet::getMaxAddress() const {
    if (rbTree.isEmpty()) return Address();
    return rbTree.getLast()->getValue();
}

int AddressSet::getNumAddressRanges() const { return rbTree.size(); }

int64_t AddressSet::getNumAddresses() const { return addressCount; }

AddressRangeIterator* AddressSet::getAddressRanges() const {
    return getAddressRanges(true);
}

AddressRangeIterator* AddressSet::getAddressRanges(bool forward) const {
    return getAddressRanges(Address(), forward);
}

AddressRangeIterator* AddressSet::getAddressRanges(const Address& start, bool forward) const {
    auto ranges = toList();
    return new AddressSetRangeIterator(ranges, start, forward);
}

AddressRange AddressSet::getRangeContaining(const Address& address) const {
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(address);
    if (entry && containsInternal(entry, address)) {
        return AddressRangeImpl(entry->getKey(), entry->getValue());
    }
    return AddressRange();
}

AddressRange AddressSet::getFirstRange() const {
    if (rbTree.isEmpty()) return AddressRange();
    return AddressRangeImpl(rbTree.getFirst()->getKey(), rbTree.getFirst()->getValue());
}

AddressRange AddressSet::getLastRange() const {
    if (rbTree.isEmpty()) return AddressRange();
    return AddressRangeImpl(rbTree.getLast()->getKey(), rbTree.getLast()->getValue());
}

Address AddressSet::findFirstAddressInCommon(const AddressSetView& set) const {
    if (set.getNumAddressRanges() > getNumAddressRanges()) {
        return set.findFirstAddressInCommon(*this);
    }
    AddressRangeIterator* it = set.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        Address start = range.getMinAddress();
        Address end = range.getMaxAddress();
        if (intersects(start, end)) {
            Address candidate = (start.compareTo(getMinAddress()) > 0) ? start : getMinAddress();
            if (candidate.compareTo(end) <= 0) {
                delete it;
                return candidate;
            }
        }
    }
    delete it;
    return Address();
}

long AddressSet::getAddressCountBefore(const Address& address) const {
    long count = 0;
    auto ranges = toList();
    for (const auto& range : ranges) {
        if (range.getMinAddress().compareTo(address) > 0) return count;
        if (range.contains(address)) {
            count += address.subtract(range.getMinAddress());
            return count;
        }
        count += range.getLength();
    }
    return count;
}

// Internal Helpers
RedBlackEntry<Address, Address>* AddressSet::createRangeNode(const Address& start, const Address& end) {
    RedBlackEntry<Address, Address>* newEntry = rbTree.getOrCreateEntry(start);
    newEntry->setValue(end);
    addressCount += (end.subtract(start) + 1);
    return newEntry;
}

void AddressSet::updateRangeEndAddress(RedBlackEntry<Address, Address>* entry, const Address& newEnd) {
    addressCount += newEnd.subtract(entry->getValue());
    entry->setValue(newEnd);
}

RedBlackEntry<Address, Address>* AddressSet::deleteRangeNode(RedBlackEntry<Address, Address>* entry) {
    RedBlackEntry<Address, Address>* successor = entry->getSuccessor();
    addressCount -= (entry->getValue().subtract(entry->getKey()) + 1);
    rbTree.removeNode(entry);
    return successor;
}

bool AddressSet::containsInternal(RedBlackEntry<Address, Address>* entry, const Address& start) const {
    return entry->getKey().compareTo(start) <= 0 && entry->getValue().compareTo(start) >= 0;
}

void AddressSet::consumeFollowOnNodes(RedBlackEntry<Address, Address>* node) {
    Address rangeEnd = node->getValue();
    RedBlackEntry<Address, Address>* nextNode = node->getSuccessor();
    while (nextNode != nullptr) {
        Address nextStart = nextNode->getKey();
        if (rangeEnd.compareTo(nextStart) < 0 && !rangeEnd.isSuccessor(nextStart)) {
            return;
        }
        Address nextEnd = nextNode->getValue();
        if (nextEnd.compareTo(rangeEnd) > 0) {
            updateRangeEndAddress(node, nextEnd);
        }
        nextNode = deleteRangeNode(nextNode);
    }
}

AddressSet::RangeCompare AddressSet::compareRange(const AddressRange& r1, const AddressRange& r2) const {
    return compareRange(r1.getMinAddress(), r1.getMaxAddress(), r2.getMinAddress(), r2.getMaxAddress());
}

AddressSet::RangeCompare AddressSet::compareRange(const Address& min1, const Address& max1, const Address& min2, const Address& max2) const {
    if (max1.compareTo(min2) < 0) return RangeCompare::RANGE1_COMPLETELY_BEFORE_RANGE2;
    if (min1.compareTo(max2) > 0) return RangeCompare::RANGE1_COMPLETELY_AFTER_RANGE2;

    int startComp = min1.compareTo(min2);
    int endComp = max1.compareTo(max2);

    if (startComp < 0) {
        if (endComp < 0) return RangeCompare::RANGE1_STARTS_BEFORE_RANGE2_ENDS_INSIDE_RANGE2;
        if (endComp > 0) return RangeCompare::RANGE1_STARTS_BEFORE_RANGE2_ENDS_AFTER_RANGE2;
        return RangeCompare::RANGE1_STARTS_BEFORE_RANGE2_ENDS_AT_RANGE2_END;
    }
    if (startComp > 0) {
        if (endComp < 0) return RangeCompare::RANGE1_STARTS_INSIDE_RANGE2_ENDS_INSIDE_RANGE2;
        if (endComp > 0) return RangeCompare::RANGE1_STARTS_INSIDE_RANGE2_ENDS_AFTER_RANGE2;
        return RangeCompare::RANGE1_STARTS_INSIDE_RANGE2_ENDS_AT_RANGE2;
    }
    if (endComp < 0) return RangeCompare::RANGE1_STARTS_AT_RANGE2_ENDS_BEFORE_RANGE2;
    if (endComp > 0) return RangeCompare::RANGE1_STARTS_AT_RANGE2_ENDS_AFTER_RANGE2;
    return RangeCompare::RANGE1_EQUALS_RANGE2;
}

bool AddressSet::useLinearAlgorithm(const AddressSetView& set) const {
    int thisSize = getNumAddressRanges();
    int thatSize = set.getNumAddressRanges();
    if (thisSize == 0) return true;
    return (thisSize + thatSize <= thatSize * std::log(thisSize) / LOGBASE2);
}

bool AddressSet::containsLinear(const AddressSetView& addrSet) const {
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(addrSet.getMinAddress());
    if (entry == nullptr) return false;

    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        while (range.getMaxAddress().compareTo(entry->getValue()) > 0) {
            entry = entry->getSuccessor();
            if (entry == nullptr) {
                delete it;
                return false;
            }
        }
        if (range.getMaxAddress().compareTo(entry->getKey()) < 0) {
            delete it;
            return false;
        }
    }
    if (it) delete it;
    return true;
}

bool AddressSet::containsBinary(const AddressSetView& addrSet) const {
    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        if (!contains(range.getMinAddress(), range.getMaxAddress())) {
            delete it;
            return false;
        }
    }
    if (it) delete it;
    return true;
}

bool AddressSet::intersectsLinear(const AddressSetView& addrSet) const {
    RedBlackEntry<Address, Address>* entry = const_cast<RedBlackTree<Address, Address>&>(rbTree).getEntryLessThanEqual(addrSet.getMinAddress());
    if (entry == nullptr) entry = rbTree.getFirst();
    if (!entry) return false;

    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        while (range.getMaxAddress().compareTo(entry->getValue()) > 0) {
            entry = entry->getSuccessor();
            if (entry == nullptr) {
                delete it;
                return false;
            }
        }
        if (range.getMaxAddress().compareTo(entry->getKey()) >= 0) {
            delete it;
            return true;
        }
    }
    if (it) delete it;
    return false;
}

bool AddressSet::intersectsBinary(const AddressSetView& addrSet) const {
    AddressRangeIterator* it = addrSet.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        if (intersects(range.getMinAddress(), range.getMaxAddress())) {
            delete it;
            return true;
        }
    }
    if (it) delete it;
    return false;
}

AddressSet AddressSet::mergeSets(const AddressSetView& addrSet) const {
    AddressSet newSet;
    AddressRangeIterator* thisS = getAddressRanges();
    AddressRangeIterator* thatS = addrSet.getAddressRanges();

    bool thisHas = thisS && thisS->hasNext();
    bool thatHas = thatS && thatS->hasNext();
    while (thisHas && thatHas) {
        const AddressRange& thisR = thisS->next();
        const AddressRange& thatR = thatS->next();
        if (thisR.getMinAddress().compareTo(thatR.getMinAddress()) <= 0) {
            newSet.add(thisR);
        } else {
            newSet.add(thatR);
        }
        thisHas = thisS->hasNext();
        thatHas = thatS->hasNext();
    }
    while (thisHas) {
        newSet.add(thisS->next());
        thisHas = thisS->hasNext();
    }
    while (thatHas) {
        newSet.add(thatS->next());
        thatHas = thatS->hasNext();
    }
    delete thisS;
    delete thatS;
    return newSet;
}

AddressSet AddressSet::deleteSets(const AddressSetView& addrSet) const {
    AddressSet newSet(*this);
    newSet.remove(addrSet);
    return newSet;
}

AddressSet AddressSet::xorSets(const AddressSetView& addrSet) const {
    return xorSet(addrSet);
}

AddressSet AddressSet::intersectLinear(const AddressSetView& addrSet) const {
    return intersect(addrSet);
}

AddressSet AddressSet::intersectBinary(const AddressSetView& addrSet) const {
    return intersect(addrSet);
}

AddressSet AddressSet::intersectRange(const Address& start, const Address& end, AddressSet& set) const {
    AddressSet result = intersectRange(start, end);
    AddressRangeIterator* it = result.getAddressRanges();
    while (it && it->hasNext()) {
        const AddressRange& range = it->next();
        set.addRange(range.getMinAddress(), range.getMaxAddress());
    }
    delete it;
    return set;
}

// AddressSetRangeIterator implementation
AddressSetRangeIterator::AddressSetRangeIterator(const std::vector<AddressRange>& ranges, const Address& start, bool forward)
    : ranges_(ranges), forward_(forward) {
    if (ranges_.empty()) {
        current_ = ranges_.end();
        return;
    }
    if (start.getAddressSpace() == nullptr || start == Address()) {
        current_ = ranges_.begin();
    } else {
        current_ = ranges_.begin();
        while (current_ != ranges_.end() && current_->getMaxAddress().compareTo(start) < 0) {
            ++current_;
        }
    }
    if (!forward_ && current_ != ranges_.end()) {
        if (current_ != ranges_.begin()) --current_;
        else current_ = ranges_.end();
    }
}

bool AddressSetRangeIterator::hasNext() const {
    return current_ != ranges_.end();
}

const AddressRange& AddressSetRangeIterator::next() {
    if (!hasNext()) throw std::runtime_error("No more elements");
    const AddressRange& result = *current_;
    if (forward_) ++current_;
    else {
        if (current_ == ranges_.begin()) current_ = ranges_.end();
        else --current_;
    }
    return result;
}

bool AddressSet::operator==(const AddressSet& other) const {
    if (getNumAddresses() != other.getNumAddresses()) return false;
    if (getNumAddressRanges() != other.getNumAddressRanges()) return false;
    auto* a = getAddressRanges();
    auto* b = other.getAddressRanges();
    bool eq = true;
    while (a->hasNext() && b->hasNext()) {
        const AddressRange& ra = a->next();
        const AddressRange& rb = b->next();
        if (!(ra == rb)) { eq = false; break; }
    }
    if (eq && (a->hasNext() || b->hasNext())) eq = false;
    delete a;
    delete b;
    return eq;
}

} // namespace ghidra
