/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PropertyMap.h
/// \brief Base interface for property maps over address ranges
/// Translated from: ghidra.program.model.util.PropertyMap
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressIterator.h>
#include <string>
#include <typeinfo>

namespace ghidra {

class PropertyMapBase {
public:
    virtual ~PropertyMapBase() = default;

    virtual std::string getName() const = 0;
    virtual const std::type_info& getValueClass() const = 0;
    virtual void clear() = 0;

    virtual bool intersects(const Address& start, const Address& end) const = 0;
    virtual bool intersects(const AddressSetView& set) const = 0;

    virtual bool removeRange(const Address& start, const Address& end) = 0;
    virtual bool remove(const Address& addr) = 0;
    virtual bool hasProperty(const Address& addr) const = 0;

    virtual Address getNextPropertyAddress(const Address& addr) const = 0;
    virtual Address getPreviousPropertyAddress(const Address& addr) const = 0;
    virtual Address getFirstPropertyAddress() const = 0;
    virtual Address getLastPropertyAddress() const = 0;

    virtual int getSize() const = 0;

    virtual AddressIterator* getPropertyIterator(const Address& start, const Address& end) const = 0;
    virtual AddressIterator* getPropertyIterator(const Address& start, const Address& end, bool forward) const = 0;
    virtual AddressIterator* getPropertyIterator() const = 0;
    virtual AddressIterator* getPropertyIterator(const AddressSetView& asv) const = 0;
    virtual AddressIterator* getPropertyIterator(const AddressSetView& asv, bool forward) const = 0;
    virtual AddressIterator* getPropertyIterator(const Address& start, bool forward) const = 0;

    virtual void moveRange(const Address& start, const Address& end, const Address& newStart) = 0;
};

} // namespace ghidra
