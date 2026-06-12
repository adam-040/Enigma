/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PropertyMapManager.h
/// \brief Property map manager interface
/// Translated from: ghidra.program.model.util.PropertyMapManager
#pragma once

#include <string>
#include <vector>

namespace ghidra {

class AddressSetPropertyMap;
class IntRangeMap;

class PropertyMapManager {
public:
    virtual ~PropertyMapManager() = default;

    virtual AddressSetPropertyMap* createAddressSetPropertyMap(const std::string& name) = 0;
    virtual IntRangeMap* createIntRangeMap(const std::string& name) = 0;
    virtual AddressSetPropertyMap* getAddressSetPropertyMap(const std::string& name) = 0;
    virtual IntRangeMap* getIntRangeMap(const std::string& name) = 0;
    virtual void deleteAddressSetPropertyMap(const std::string& name) = 0;
    virtual void deleteIntRangeMap(const std::string& name) = 0;
};

} // namespace ghidra
