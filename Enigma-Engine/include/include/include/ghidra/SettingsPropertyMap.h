/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SettingsPropertyMap.h
/// \brief Property map interface for storing Settings objects.
#pragma once

#include "ghidra/PropertyMap.h"
#include "ghidra/Settings.h"

namespace ghidra {

/**
 * Property map interface for storing Settings objects.
 * Translated from: ghidra.program.model.util.SettingsPropertyMap
 */
class SettingsPropertyMap : public PropertyMapBase {
public:
    virtual void add(const Address& addr, Settings* value) = 0;
    virtual Settings* getSettings(const Address& addr) const = 0;
};

} // namespace ghidra
