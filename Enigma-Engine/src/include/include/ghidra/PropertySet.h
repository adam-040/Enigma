/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PropertySet.h
/// \brief Interface for accessing named properties of various types
/// Translated from: ghidra.program.model.util.PropertySet
#pragma once

#include <ghidra/Saveable.h>
#include <string>
#include <vector>

namespace ghidra {

class PropertySet {
public:
    virtual ~PropertySet() = default;

    virtual void setProperty(const std::string& name, const Saveable& value) = 0;
    virtual void setProperty(const std::string& name, const std::string& value) = 0;
    virtual void setProperty(const std::string& name, int32_t value) = 0;
    virtual void setProperty(const std::string& name) = 0;

    virtual Saveable* getObjectProperty(const std::string& name) const = 0;
    virtual std::string getStringProperty(const std::string& name) const = 0;
    virtual int32_t getIntProperty(const std::string& name) const = 0;

    virtual bool hasProperty(const std::string& name) const = 0;
    virtual bool getVoidProperty(const std::string& name) const = 0;

    virtual std::vector<std::string> propertyNames() const = 0;

    virtual void removeProperty(const std::string& name) = 0;
};

} // namespace ghidra
