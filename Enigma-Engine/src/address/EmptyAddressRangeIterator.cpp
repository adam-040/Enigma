/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/EmptyAddressRangeIterator.h"

namespace ghidra {

bool EmptyAddressRangeIterator::hasNext() const {
    return false;
}

const AddressRange& EmptyAddressRangeIterator::next() {
    static AddressRange EMPTY_RANGE;
    return EMPTY_RANGE;
}

EmptyAddressRangeIterator& EmptyAddressRangeIterator::instance() {
    static EmptyAddressRangeIterator INSTANCE;
    return INSTANCE;
}

} // namespace ghidra
