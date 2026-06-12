/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file SymmetricDifferenceAddressSetView.cpp
/// \brief Implementation of the lazy symmetric difference view (A ⊕ B)

#include <ghidra/SymmetricDifferenceAddressSetView.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

SymmetricDifferenceAddressSetView::SymmetricDifferenceAddressSetView(
    const AddressSetView& a, const AddressSetView& b)
    : setA_(a), setB_(b) {}

bool SymmetricDifferenceAddressSetView::contains(const Address& addr) const {
    bool inA = setA_.contains(addr);
    bool inB = setB_.contains(addr);
    return inA != inB; // XOR: in one but not both
}

std::vector<AddressRange> SymmetricDifferenceAddressSetView::getRanges() const {
    if (setA_.isEmpty() && setB_.isEmpty()) return {};
    if (setA_.isEmpty()) {
        // Return all of B's ranges
        std::vector<AddressRange> result;
        AddressRangeIterator* it = setB_.getAddressRanges();
        while (it && it->hasNext()) {
            result.push_back(it->next());
        }
        delete it;
        return result;
    }
    if (setB_.isEmpty()) {
        // Return all of A's ranges
        std::vector<AddressRange> result;
        AddressRangeIterator* it = setA_.getAddressRanges();
        while (it && it->hasNext()) {
            result.push_back(it->next());
        }
        delete it;
        return result;
    }

    // XOR = (A union B) minus (A intersect B)
    // Build union
    AddressSet unionSet;
    AddressRangeIterator* itA = setA_.getAddressRanges();
    while (itA && itA->hasNext()) {
        const AddressRange& r = itA->next();
        unionSet.addRange(r.getMinAddress(), r.getMaxAddress());
    }
    delete itA;

    AddressRangeIterator* itB = setB_.getAddressRanges();
    while (itB && itB->hasNext()) {
        const AddressRange& r = itB->next();
        unionSet.addRange(r.getMinAddress(), r.getMaxAddress());
    }
    delete itB;

    // Build intersection and subtract from union
    itA = setA_.getAddressRanges();
    while (itA && itA->hasNext()) {
        const AddressRange& rangeA = itA->next();
        AddressRangeIterator* itB2 = setB_.getAddressRanges();
        while (itB2 && itB2->hasNext()) {
            const AddressRange& rangeB = itB2->next();
            if (rangeB.getMinAddress() > rangeA.getMaxAddress()) break;
            if (rangeB.getMaxAddress() < rangeA.getMinAddress()) continue;

            Address iMin = (rangeA.getMinAddress() > rangeB.getMinAddress())
                ? rangeA.getMinAddress() : rangeB.getMinAddress();
            Address iMax = (rangeA.getMaxAddress() < rangeB.getMaxAddress())
                ? rangeA.getMaxAddress() : rangeB.getMaxAddress();
            if (iMin <= iMax) {
                unionSet.deleteRange(iMin, iMax);
            }
        }
        delete itB2;
    }
    delete itA;

    return unionSet.toList();
}

} // namespace ghidra
