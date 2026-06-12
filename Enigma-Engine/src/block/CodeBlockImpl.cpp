/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/CodeBlockImpl.h>
#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockReference.h>
#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/block/SimpleSourceReferenceIterator.h>
#include <ghidra/block/SimpleDestReferenceIterator.h>
#include <ghidra/RefType.h>
#include <ghidra/Program.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <algorithm>

namespace ghidra {

CodeBlockImpl::CodeBlockImpl(CodeBlockModel* model, Program* program, const std::string& name)
    : name_(name), model_(model), program_(program) {
}

CodeBlockImpl::CodeBlockImpl(CodeBlockModel* model, Program* program, const std::string& name,
                             const AddressSetView& addrSet)
    : name_(name), model_(model), program_(program), addressSet_(addrSet) {
}

Address CodeBlockImpl::getMinAddress() const {
    return addressSet_.getMinAddress();
}

Address CodeBlockImpl::getMaxAddress() const {
    return addressSet_.getMaxAddress();
}

Address CodeBlockImpl::getFirstStartAddress() const {
    if (!startAddresses_.empty()) {
        return startAddresses_[0];
    }
    return addressSet_.getMinAddress();
}

Address* CodeBlockImpl::getStartAddresses() const {
    Address* arr = new Address[startAddresses_.size() + 1];
    for (size_t i = 0; i < startAddresses_.size(); ++i) {
        arr[i] = startAddresses_[i];
    }
    arr[startAddresses_.size()] = Address(); // sentinel: invalid address marks end
    return arr;
}

bool CodeBlockImpl::contains(Address addr) const {
    return addressSet_.contains(addr);
}

CodeBlockReferenceIterator* CodeBlockImpl::getSources(TaskMonitor& monitor) {
    return new SimpleSourceReferenceIterator(this, false, monitor);
}

CodeBlockReferenceIterator* CodeBlockImpl::getDestinations(TaskMonitor& monitor) {
    return new SimpleDestReferenceIterator(this, false, monitor);
}

int CodeBlockImpl::getNumSources(TaskMonitor& monitor) {
    std::unique_ptr<CodeBlockReferenceIterator> iter(getSources(monitor));
    int count = 0;
    while (iter->hasNext()) {
        iter->next();
        ++count;
    }
    return count;
}

int CodeBlockImpl::getNumDestinations(TaskMonitor& monitor) {
    std::unique_ptr<CodeBlockReferenceIterator> iter(getDestinations(monitor));
    int count = 0;
    while (iter->hasNext()) {
        iter->next();
        ++count;
    }
    return count;
}

bool CodeBlockImpl::hasValidSymbol() const {
    return !name_.empty();
}

int CodeBlockImpl::compareTo(const CodeBlock& other) const {
    Address myMin = getMinAddress();
    Address otherMin = other.getMinAddress();
    if (myMin.isValid() && otherMin.isValid()) {
        return myMin.compareTo(otherMin);
    }
    if (!myMin.isValid() && !otherMin.isValid()) {
        return 0;
    }
    return myMin.isValid() ? -1 : 1;
}

size_t CodeBlockImpl::hash() const {
    Address min = getMinAddress();
    return min.isValid() ? static_cast<size_t>(min.getOffset()) : 0;
}

void CodeBlockImpl::addStartAddress(const Address& addr) {
    startAddresses_.push_back(addr);
}

void CodeBlockImpl::setAddressSet(const AddressSetView& addrSet) {
    addressSet_ = AddressSet(addrSet);
}

void CodeBlockImpl::addRange(const Address& start, const Address& end) {
    addressSet_.addRange(start, end);
}

} // namespace ghidra
