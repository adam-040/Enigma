/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file DifferenceAddressSetView.cpp
/// \brief Implementation of the lazy set difference view (A \ B)

#include <ghidra/DifferenceAddressSetView.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

DifferenceAddressSetView::DifferenceAddressSetView(const AddressSetView& a, const AddressSetView& b)
    : setA_(a), setB_(b) {}

bool DifferenceAddressSetView::contains(const Address& addr) const {
    return setA_.contains(addr) && !setB_.contains(addr);
}

std::vector<AddressRange> DifferenceAddressSetView::getRanges() const {
    if (setA_.isEmpty()) return {};

    // Start with all of A's ranges, then subtract B's ranges
    AddressSet result;
    AddressRangeIterator* itA = setA_.getAddressRanges();
    while (itA && itA->hasNext()) {
        const AddressRange& range = itA->next();
        result.addRange(range.getMinAddress(), range.getMaxAddress());
    }
    delete itA;

    if (!setB_.isEmpty()) {
        AddressRangeIterator* itB = setB_.getAddressRanges();
        while (itB && itB->hasNext()) {
            const AddressRange& range = itB->next();
            result.deleteRange(range.getMinAddress(), range.getMaxAddress());
        }
        delete itB;
    }

    return result.toList();
}

} // namespace ghidra
