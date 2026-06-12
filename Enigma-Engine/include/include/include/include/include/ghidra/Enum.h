/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Enum.h
/// \brief Enum interface.
#pragma once

#include "DataType.h"
#include "EnumSignedState.h"
#include <string>
#include <vector>
#include <stdexcept>

namespace ghidra {

/**
 * Enum interface.
 * Translated from: ghidra.program.model.data.Enum
 */
class Enum : public virtual DataType {
public:
    virtual ~Enum() = default;

    using DataType::getName;
    virtual long long getValue(const std::string& name) const = 0;
    virtual std::string getName(long long value) const = 0;
    virtual std::vector<std::string> getNames(long long value) const = 0;
    virtual std::string getComment(const std::string& name) const = 0;
    
    virtual std::vector<long long> getValues() const = 0;
    virtual std::vector<std::string> getNames() const = 0;
    
    virtual int getCount() const = 0;
    
    virtual void add(const std::string& name, long long value) = 0;
    virtual void add(const std::string& name, long long value, const std::string& comment) = 0;
    virtual void remove(const std::string& name) = 0;
    
    virtual bool contains(const std::string& name) const = 0;
    virtual bool contains(long long value) const = 0;
    
    virtual bool isSigned() const = 0;
    virtual EnumSignedState getSignedState() const = 0;
    
    virtual long long getMaxPossibleValue() const = 0;
    virtual long long getMinPossibleValue() const = 0;
    virtual int getMinimumPossibleLength() const = 0;
};

} // namespace ghidra
