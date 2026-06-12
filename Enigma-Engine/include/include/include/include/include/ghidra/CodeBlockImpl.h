/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/CodeBlock.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <vector>

namespace ghidra {

class CodeBlockModel;

class CodeBlockImpl : public CodeBlock {
public:
    CodeBlockImpl(CodeBlockModel* model, const std::vector<Address>& starts, AddressSetView* body);
    CodeBlockImpl(CodeBlockModel* model, Address start, AddressSetView* body);

    Address getFirstStartAddress() const override;
    std::vector<Address> getStartAddresses() const override { return starts_; }
    std::string getName() const override;
    FlowType getFlowType() const override;

    int getNumSources(TaskMonitor* monitor) override;
    CodeBlockReferenceIterator* getSources(TaskMonitor* monitor) override;
    int getNumDestinations(TaskMonitor* monitor) override;
    CodeBlockReferenceIterator* getDestinations(TaskMonitor* monitor) override;
    CodeBlockModel* getModel() const override { return model_; }

    // AddressSetView interface
    bool contains(const Address& addr) const override;
    bool contains(const Address& start, const Address& end) const override;
    bool contains(const AddressSetView& rangeSet) const override;
    bool isEmpty() const override;
    Address getMinAddress() const override;
    Address getMaxAddress() const override;
    int getNumAddressRanges() const override;
    int64_t getNumAddresses() const override;
    AddressRangeIterator* getAddressRanges() const override;
    AddressRangeIterator* getAddressRanges(bool forward) const override;
    AddressRangeIterator* getAddressRanges(const Address& start, bool forward) const override;
    bool intersects(const AddressSetView& other) const override;
    bool intersects(const Address& start, const Address& end) const override;
    AddressSet intersect(const AddressSetView& view) const override;
    AddressSet intersectRange(const Address& start, const Address& end) const override;
    AddressSet unionSet(const AddressSetView& addrSet) const override;
    AddressSet subtract(const AddressSetView& addrSet) const override;
    AddressSet xorSet(const AddressSetView& addrSet) const override;
    bool hasSameAddresses(const AddressSetView& addrSet) const override;
    AddressRange getFirstRange() const override;
    AddressRange getLastRange() const override;
    AddressRange getRangeContaining(const Address& address) const override;
    Address findFirstAddressInCommon(const AddressSetView& set) const override;

    std::string toString() const;
    bool operator==(const CodeBlockImpl& other) const;
    std::size_t hashCode() const { return starts_[0].hash(); }

private:
    CodeBlockModel* model_;
    std::vector<Address> starts_;
    AddressSetView* set_;
};

} // namespace ghidra
