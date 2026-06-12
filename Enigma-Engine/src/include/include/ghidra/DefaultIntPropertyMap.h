/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DefaultIntPropertyMap.h
/// \brief Default implementation of IntPropertyMap backed by std::map
/// Translated from: ghidra.program.model.util.DefaultIntPropertyMap
#pragma once

#include <ghidra/IntPropertyMap.h>
#include <ghidra/DefaultPropertyMap.h>
#include <ghidra/NoValueException.h>
#include <map>
#include <string>

namespace ghidra {

class DefaultIntPropertyMap : public IntPropertyMap, public DefaultPropertyMap {
private:
    std::string name_;
    std::map<uint64_t, int32_t> map_;

public:
    explicit DefaultIntPropertyMap(const std::string& name);
    ~DefaultIntPropertyMap() override = default;

    std::string getName() const override;
    const std::type_info& getValueClass() const override;
    void clear() override;

    void add(const Address& addr, int32_t value) override;
    int32_t getInt(const Address& addr) override;

    bool intersects(const Address& start, const Address& end) const override;
    bool intersects(const AddressSetView& set) const override;
    bool removeRange(const Address& start, const Address& end) override;
    bool remove(const Address& addr) override;
    bool hasProperty(const Address& addr) const override;

    Address getNextPropertyAddress(const Address& addr) const override;
    Address getPreviousPropertyAddress(const Address& addr) const override;
    Address getFirstPropertyAddress() const override;
    Address getLastPropertyAddress() const override;

    int getSize() const override;

    AddressIterator* getPropertyIterator(const Address& start, const Address& end) const override;
    AddressIterator* getPropertyIterator(const Address& start, const Address& end, bool forward) const override;
    AddressIterator* getPropertyIterator() const override;
    AddressIterator* getPropertyIterator(const AddressSetView& asv) const override;
    AddressIterator* getPropertyIterator(const AddressSetView& asv, bool forward) const override;
    AddressIterator* getPropertyIterator(const Address& start, bool forward) const override;

    void moveRange(const Address& start, const Address& end, const Address& newStart) override;
};

} // namespace ghidra
