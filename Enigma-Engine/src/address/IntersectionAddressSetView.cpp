/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file IntersectionAddressSetView.cpp
/// \brief Implementation of the lazy intersection view (A ∩ B)

#include <ghidra/IntersectionAddressSetView.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

IntersectionAddressSetView::IntersectionAddressSetView(const AddressSetView& a, const AddressSetView& b)
    : setA_(a), setB_(b) {}

bool IntersectionAddressSetView::contains(const Address& addr) const {
    return setA_.contains(addr) && setB_.contains(addr);
}

std::vector<AddressRange> IntersectionAddressSetView::getRanges() const {
    if (setA_.isEmpty() || setB_.isEmpty()) return {};

    // Walk through A's ranges and intersect each with B
    AddressSet result;
    AddressRangeIterator* itA = setA_.getAddressRanges();
    while (itA && itA->hasNext()) {
        const AddressRange& rangeA = itA->next();
        // Check each of B's ranges for overlap with this A range
        AddressRangeIterator* itB = setB_.getAddressRanges();
        while (itB && itB->hasNext()) {
            const AddressRange& rangeB = itB->next();
            // If B range is past the end of A range, stop
            if (rangeB.getMinAddress() > rangeA.getMaxAddress()) break;
            // If B range is before the start of A range, skip
            if (rangeB.getMaxAddress() < rangeA.getMinAddress()) continue;

            // Compute intersection
            Address iMin = (rangeA.getMinAddress() > rangeB.getMinAddress())
                ? rangeA.getMinAddress() : rangeB.getMinAddress();
            Address iMax = (rangeA.getMaxAddress() < rangeB.getMaxAddress())
                ? rangeA.getMaxAddress() : rangeB.getMaxAddress();
            if (iMin <= iMax) {
                result.addRange(iMin, iMax);
            }
        }
        delete itB;
    }
    delete itA;

    return result.toList();
}

} // namespace ghidra
