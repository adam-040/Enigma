/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DatatypeFilter.h
/// \brief Interface for data-type filtering (selecting a specific class of data-type)
/// Translated from: ghidra.program.model.lang.protorules.DatatypeFilter
#pragma once

#include <ghidra/Encoder.h>
#include <ghidra/DataType.h>

namespace ghidra {

class DatatypeFilter {
public:
    virtual ~DatatypeFilter() = default;

    virtual DatatypeFilter* clone() const = 0;
    virtual bool isEquivalent(const DatatypeFilter& op) const = 0;
    virtual bool filter(DataType* dt) = 0;
    virtual void encode(Encoder& encoder) = 0;
    virtual void restoreXml(class XmlPullParser& parser) = 0;

    static DatatypeFilter* restoreFilterXml(class XmlPullParser& parser);
};

} // namespace ghidra
