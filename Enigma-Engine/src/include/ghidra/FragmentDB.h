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

#include <ghidra/ProgramFragment.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <vector>

namespace ghidra {

class ModuleManager;

class FragmentDB : public ProgramFragment {
public:
    FragmentDB(ModuleManager* moduleMgr, long key, const std::string& name);
    ~FragmentDB() override = default;

    // Group implementation
    std::string getComment() const override { return comment_; }
    void setComment(const std::string& comment) override { comment_ = comment; }

    std::string getName() const override { return name_; }
    void setName(const std::string& name) override;

    bool contains(CodeUnit* codeUnit) const override;

    int getNumParents() const override;
    std::vector<ProgramModule*> getParents() const override;
    std::vector<std::string> getParentNames() const override;

    std::string getTreeName() const override;
    bool isDeleted() const override { return deleted_; }
    void setDeleted(bool val) { deleted_ = val; }

    Address getMinAddress() const override { return addrSet_.getMinAddress(); }
    Address getMaxAddress() const override { return addrSet_.getMaxAddress(); }

    // AddressSetView implementation (forwarding to addrSet_)
    bool contains(const Address& addr) const override { return addrSet_.contains(addr); }
    bool contains(const Address& start, const Address& end) const override { return addrSet_.contains(start, end); }
    bool contains(const AddressSetView& rangeSet) const override { return addrSet_.contains(rangeSet); }
    bool isEmpty() const override { return addrSet_.isEmpty(); }
    int getNumAddressRanges() const override { return addrSet_.getNumAddressRanges(); }
    int64_t getNumAddresses() const override { return addrSet_.getNumAddresses(); }
    AddressRangeIterator* getAddressRanges() const override { return addrSet_.getAddressRanges(); }
    AddressRangeIterator* getAddressRanges(bool forward) const override { return addrSet_.getAddressRanges(forward); }
    AddressRangeIterator* getAddressRanges(const Address& start, bool forward) const override { return addrSet_.getAddressRanges(start, forward); }
    bool intersects(const AddressSetView& other) const override { return addrSet_.intersects(other); }
    bool intersects(const Address& start, const Address& end) const override { return addrSet_.intersects(start, end); }
    AddressSet intersect(const AddressSetView& view) const override { return addrSet_.intersect(view); }
    AddressSet intersectRange(const Address& start, const Address& end) const override { return addrSet_.intersectRange(start, end); }
    AddressSet unionSet(const AddressSetView& addrSet) const override { return addrSet_.unionSet(addrSet); }
    AddressSet subtract(const AddressSetView& addrSet) const override { return addrSet_.subtract(addrSet); }
    AddressSet xorSet(const AddressSetView& addrSet) const override { return addrSet_.xorSet(addrSet); }
    bool hasSameAddresses(const AddressSetView& addrSet) const override { return addrSet_.hasSameAddresses(addrSet); }
    AddressRange getFirstRange() const override { return addrSet_.getFirstRange(); }
    AddressRange getLastRange() const override { return addrSet_.getLastRange(); }
    AddressRange getRangeContaining(const Address& address) const override { return addrSet_.getRangeContaining(address); }
    Address findFirstAddressInCommon(const AddressSetView& set) const override { return addrSet_.findFirstAddressInCommon(set); }

    // ProgramFragment specific implementation
    void move(const Address& min, const Address& max) override;

    // Range operations called by ModuleManager
    void addRange(const AddressRange& range) { addrSet_.add(range); }
    void addRange(const Address& start, const Address& end) { addrSet_.add(start, end); }
    void removeRange(const Address& start, const Address& end) { addrSet_.remove(start, end); }
    void clearRanges() { addrSet_.clear(); }

    long getKey() const { return key_; }
    const AddressSet& getAddressSetInternal() const { return addrSet_; }
    AddressSet& getAddressSetInternalMutable() { return addrSet_; }

private:
    ModuleManager* moduleMgr_ = nullptr;
    long key_ = 0;
    std::string name_;
    std::string comment_;
    bool deleted_ = false;
    AddressSet addrSet_;
};

} // namespace ghidra
