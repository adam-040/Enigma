/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file UnionAddressRangeIterator.cpp
/// \brief Implementation of the union merge iterator for two sorted range streams

#include <ghidra/UnionAddressRangeIterator.h>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

UnionAddressRangeIterator::UnionAddressRangeIterator(
    AddressRangeIterator* iter1, AddressRangeIterator* iter2, bool ownsIterators)
    : iter1_(iter1), iter2_(iter2), ownsIterators_(ownsIterators),
      has1_(false), has2_(false), nextReady_(false) {
    loadPeek1();
    loadPeek2();
    computeNext();
}

UnionAddressRangeIterator::~UnionAddressRangeIterator() {
    if (ownsIterators_) {
        delete iter1_;
        delete iter2_;
    }
}

void UnionAddressRangeIterator::loadPeek1() {
    if (iter1_ && iter1_->hasNext()) {
        const AddressRange& r = iter1_->next();
        peek1_ = AddressRangeImpl(r.getMinAddress(), r.getMaxAddress());
        has1_ = true;
    } else {
        has1_ = false;
    }
}

void UnionAddressRangeIterator::loadPeek2() {
    if (iter2_ && iter2_->hasNext()) {
        const AddressRange& r = iter2_->next();
        peek2_ = AddressRangeImpl(r.getMinAddress(), r.getMaxAddress());
        has2_ = true;
    } else {
        has2_ = false;
    }
}

void UnionAddressRangeIterator::computeNext() {
    nextReady_ = false;

    if (!has1_ && !has2_) return;

    // Pick the range with the smaller start address
    Address mergeMin, mergeMax;
    if (!has1_) {
        mergeMin = peek2_.getMinAddress();
        mergeMax = peek2_.getMaxAddress();
        loadPeek2();
    } else if (!has2_) {
        mergeMin = peek1_.getMinAddress();
        mergeMax = peek1_.getMaxAddress();
        loadPeek1();
    } else if (peek1_.getMinAddress() <= peek2_.getMinAddress()) {
        mergeMin = peek1_.getMinAddress();
        mergeMax = peek1_.getMaxAddress();
        loadPeek1();
    } else {
        mergeMin = peek2_.getMinAddress();
        mergeMax = peek2_.getMaxAddress();
        loadPeek2();
    }

    // Keep extending the merged range as long as the next range from either
    // iterator overlaps or is adjacent to the current merged range
    bool extended = true;
    while (extended) {
        extended = false;

        if (has1_) {
            // Check overlap or adjacency: peek1.min <= mergeMax + 1
            Address pMin = peek1_.getMinAddress();
            if (pMin <= mergeMax || mergeMax.isSuccessor(pMin)) {
                // Extend if peek1.max > mergeMax
                if (peek1_.getMaxAddress() > mergeMax) {
                    mergeMax = peek1_.getMaxAddress();
                }
                loadPeek1();
                extended = true;
            }
        }

        if (has2_) {
            Address pMin = peek2_.getMinAddress();
            if (pMin <= mergeMax || mergeMax.isSuccessor(pMin)) {
                if (peek2_.getMaxAddress() > mergeMax) {
                    mergeMax = peek2_.getMaxAddress();
                }
                loadPeek2();
                extended = true;
            }
        }
    }

    nextResult_ = AddressRangeImpl(mergeMin, mergeMax);
    nextReady_ = true;
}

bool UnionAddressRangeIterator::hasNext() const {
    return nextReady_;
}

const AddressRange& UnionAddressRangeIterator::next() {
    if (!nextReady_) {
        throw std::runtime_error("UnionAddressRangeIterator: no more elements");
    }
    // Copy current result, then advance
    static thread_local AddressRangeImpl result;
    result = nextResult_;
    computeNext();
    return result;
}

} // namespace ghidra
