/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file TwoWayBreakdownAddressRangeIterator.cpp
/// \brief Implementation of the range breakdown iterator with source tagging

#include <ghidra/TwoWayBreakdownAddressRangeIterator.h>
#include <stdexcept>
#include <algorithm>

namespace ghidra {

TwoWayBreakdownAddressRangeIterator::TwoWayBreakdownAddressRangeIterator(
    AddressRangeIterator* left, AddressRangeIterator* right, bool ownsIterators)
    : leftIter_(left), rightIter_(right), ownsIterators_(ownsIterators),
      hasLeft_(false), hasRight_(false), nextReady_(false) {
    loadLeft();
    loadRight();
    computeNext();
}

TwoWayBreakdownAddressRangeIterator::~TwoWayBreakdownAddressRangeIterator() {
    if (ownsIterators_) {
        delete leftIter_;
        delete rightIter_;
    }
}

void TwoWayBreakdownAddressRangeIterator::loadLeft() {
    if (leftIter_ && leftIter_->hasNext()) {
        const AddressRange& r = leftIter_->next();
        peekLeft_ = AddressRangeImpl(r.getMinAddress(), r.getMaxAddress());
        hasLeft_ = true;
    } else {
        hasLeft_ = false;
    }
}

void TwoWayBreakdownAddressRangeIterator::loadRight() {
    if (rightIter_ && rightIter_->hasNext()) {
        const AddressRange& r = rightIter_->next();
        peekRight_ = AddressRangeImpl(r.getMinAddress(), r.getMaxAddress());
        hasRight_ = true;
    } else {
        hasRight_ = false;
    }
}

void TwoWayBreakdownAddressRangeIterator::consumeLeft(const Address& throughAddr) {
    if (!hasLeft_) return;
    if (throughAddr >= peekLeft_.getMaxAddress()) {
        // Fully consumed
        loadLeft();
    } else {
        // Partially consumed: advance left's start past throughAddr
        Address newMin = throughAddr.next();
        peekLeft_ = AddressRangeImpl(newMin, peekLeft_.getMaxAddress());
    }
}

void TwoWayBreakdownAddressRangeIterator::consumeRight(const Address& throughAddr) {
    if (!hasRight_) return;
    if (throughAddr >= peekRight_.getMaxAddress()) {
        loadRight();
    } else {
        Address newMin = throughAddr.next();
        peekRight_ = AddressRangeImpl(newMin, peekRight_.getMaxAddress());
    }
}

void TwoWayBreakdownAddressRangeIterator::computeNext() {
    nextReady_ = false;

    if (!hasLeft_ && !hasRight_) return;

    // Case 1: Only left remaining
    if (!hasRight_) {
        nextEntry_ = Entry(peekLeft_, Which::LEFT);
        loadLeft();
        nextReady_ = true;
        return;
    }

    // Case 2: Only right remaining
    if (!hasLeft_) {
        nextEntry_ = Entry(peekRight_, Which::RIGHT);
        loadRight();
        nextReady_ = true;
        return;
    }

    Address lMin = peekLeft_.getMinAddress();
    Address lMax = peekLeft_.getMaxAddress();
    Address rMin = peekRight_.getMinAddress();
    Address rMax = peekRight_.getMaxAddress();

    // Case 3: Left starts before right - emit LEFT-only prefix
    if (lMin < rMin) {
        if (lMax < rMin) {
            // No overlap at all
            nextEntry_ = Entry(peekLeft_, Which::LEFT);
            loadLeft();
        } else {
            // Left starts before right, emit the prefix [lMin, rMin-1] as LEFT
            Address prefixEnd = rMin.previous();
            nextEntry_ = Entry(AddressRangeImpl(lMin, prefixEnd), Which::LEFT);
            consumeLeft(prefixEnd);
        }
        nextReady_ = true;
        return;
    }

    // Case 4: Right starts before left - emit RIGHT-only prefix
    if (rMin < lMin) {
        if (rMax < lMin) {
            nextEntry_ = Entry(peekRight_, Which::RIGHT);
            loadRight();
        } else {
            Address prefixEnd = lMin.previous();
            nextEntry_ = Entry(AddressRangeImpl(rMin, prefixEnd), Which::RIGHT);
            consumeRight(prefixEnd);
        }
        nextReady_ = true;
        return;
    }

    // Case 5: Both start at the same address - emit BOTH overlap
    Address overlapEnd = (lMax < rMax) ? lMax : rMax;
    nextEntry_ = Entry(AddressRangeImpl(lMin, overlapEnd), Which::BOTH);
    consumeLeft(overlapEnd);
    consumeRight(overlapEnd);
    nextReady_ = true;
}

bool TwoWayBreakdownAddressRangeIterator::hasNext() const {
    return nextReady_;
}

const AddressRange& TwoWayBreakdownAddressRangeIterator::next() {
    if (!nextReady_) {
        throw std::runtime_error("TwoWayBreakdownAddressRangeIterator: no more elements");
    }
    static thread_local Entry resultHolder;
    resultHolder = nextEntry_;
    computeNext();
    return resultHolder.range;
}

TwoWayBreakdownAddressRangeIterator::Entry
TwoWayBreakdownAddressRangeIterator::nextEntry() {
    if (!nextReady_) {
        throw std::runtime_error("TwoWayBreakdownAddressRangeIterator: no more elements");
    }
    Entry result = nextEntry_;
    computeNext();
    return result;
}

} // namespace ghidra
