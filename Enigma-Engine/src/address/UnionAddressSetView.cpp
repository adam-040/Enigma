/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file UnionAddressSetView.cpp
/// \brief Implementation of the lazy union address set view

#include <ghidra/UnionAddressSetView.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

UnionAddressSetView::UnionAddressSetView(const AddressSetView& a, const AddressSetView& b) {
    sets_.push_back(&a);
    sets_.push_back(&b);
}

UnionAddressSetView::UnionAddressSetView(const std::vector<const AddressSetView*>& sets)
    : sets_(sets) {}

bool UnionAddressSetView::contains(const Address& addr) const {
    for (const auto* set : sets_) {
        if (set->contains(addr)) return true;
    }
    return false;
}

std::vector<AddressRange> UnionAddressSetView::getRanges() const {
    if (sets_.empty()) return {};

    // Collect all ranges from all sets, then merge them
    // We use an AddressSet to do the merge since it handles overlap/adjacency
    AddressSet merged;
    for (const auto* set : sets_) {
        if (set->isEmpty()) continue;
        AddressRangeIterator* it = set->getAddressRanges();
        while (it && it->hasNext()) {
            const AddressRange& range = it->next();
            merged.addRange(range.getMinAddress(), range.getMaxAddress());
        }
        delete it;
    }

    return merged.toList();
}

} // namespace ghidra
