/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PropertyMapManagerImpl.h
/// \brief Implementation of property map manager
/// Translated from: ghidra.program.database.properties.DBPropertyMapManager
#pragma once

#include <ghidra/PropertyMapManager.h>
#include <ghidra/AddressSetPropertyMap.h>
#include <ghidra/AddressSet.h>
#include <ghidra/IntRangeMap.h>
#include <ghidra/ManagerDB.h>
#include <unordered_map>
#include <memory>

namespace ghidra {

class Program;
class TaskMonitor;

class AddressSetPropertyMapImpl : public AddressSetPropertyMap {
public:
    explicit AddressSetPropertyMapImpl(const std::string& name);

    const std::string& getName() const override { return name_; }

    void add(const Address& start, const Address& end) override;
    void add(const AddressSetView& addressSet) override;
    void set(const AddressSetView& addressSet) override;

    void remove(const Address& start, const Address& end) override;
    void remove(const AddressSetView& addressSet) override;

    AddressSet getAddressSet() override;
    AddressIterator* getAddresses() override;
    AddressRangeIterator* getAddressRanges() override;

    void clear() override;
    bool contains(const Address& addr) override;

private:
    std::string name_;
    AddressSet set_;
};

class IntRangeMapImpl : public IntRangeMap {
public:
    struct Range { Address start; Address end; int64_t value; };

    explicit IntRangeMapImpl(const std::string& name) : name_(name) {}
    const std::string& getName() const override { return name_; }
    int64_t getValue(Address addr) override;
    void setValue(Address start, Address end, int64_t value) override;
    void clearValue(Address start, Address end) override;
    const std::vector<Range>& getRanges() const { return ranges_; }
private:
    std::string name_;
    std::vector<Range> ranges_;
};

class PropertyMapManagerImpl : public PropertyMapManager, public ManagerDB {
public:
    PropertyMapManagerImpl() = default;
    explicit PropertyMapManagerImpl(Program* program) : program_(program) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { if (all) { addrSetMaps_.clear(); intRangeMaps_.clear(); } }
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return static_cast<int>(addrSetMaps_.size() + intRangeMaps_.size()); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "PropertyMapManager"; }

    AddressSetPropertyMap* createAddressSetPropertyMap(const std::string& name) override;

    IntRangeMap* createIntRangeMap(const std::string& name) override;

    AddressSetPropertyMap* getAddressSetPropertyMap(const std::string& name) override;

    IntRangeMap* getIntRangeMap(const std::string& name) override;

    void deleteAddressSetPropertyMap(const std::string& name) override;
    void deleteIntRangeMap(const std::string& name) override;

    const std::unordered_map<std::string, std::unique_ptr<IntRangeMapImpl>>& getIntRangeMaps() const { return intRangeMaps_; }
    const std::unordered_map<std::string, std::unique_ptr<AddressSetPropertyMapImpl>>& getAddrSetMaps() const { return addrSetMaps_; }

private:
    Program* program_ = nullptr;
    std::unordered_map<std::string, std::unique_ptr<AddressSetPropertyMapImpl>> addrSetMaps_;
    std::unordered_map<std::string, std::unique_ptr<IntRangeMapImpl>> intRangeMaps_;
    int revision_ = 0;
};

} // namespace ghidra
