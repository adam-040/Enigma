/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/EmptyAddressIterator.h"

namespace ghidra {

EmptyAddressIterator::EmptyAddressIterator() : AddressIterator() {}

bool EmptyAddressIterator::hasNext() const {
    return false;
}

Address EmptyAddressIterator::next() {
    return Address();
}

Address EmptyAddressIterator::current() const {
    return Address();
}

void EmptyAddressIterator::reset() {}

size_t EmptyAddressIterator::remaining() const {
    return 0;
}

EmptyAddressIterator& EmptyAddressIterator::instance() {
    static EmptyAddressIterator INSTANCE;
    return INSTANCE;
}

} // namespace ghidra
