/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DefaultPropertyMap.h
/// \brief Common base for default property-map implementations
/// Translated from: ghidra.program.model.util.DefaultPropertyMap (non-template portion)
#pragma once

#include <string>

namespace ghidra {

class DefaultPropertyMap {
protected:
    std::string description_;

public:
    DefaultPropertyMap() = default;
    virtual ~DefaultPropertyMap() = default;

    virtual std::string getName() const = 0;
    virtual void clear() = 0;
    virtual int getSize() const = 0;

    void setDescription(const std::string& description) { description_ = description; }
    std::string getDescription() const { return description_; }
};

} // namespace ghidra
