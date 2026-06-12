/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file QualifierFilter.h
/// \brief Interface for qualifier filtering (prototype-position criteria)
/// Translated from: ghidra.program.model.lang.protorules.QualifierFilter
#pragma once

#include <ghidra/Encoder.h>
#include <ghidra/PrototypePieces.h>

namespace ghidra {

class QualifierFilter {
public:
    virtual ~QualifierFilter() = default;

    virtual QualifierFilter* clone() const = 0;
    virtual bool isEquivalent(const QualifierFilter& op) const = 0;
    virtual bool filter(const PrototypePieces& proto, int pos) = 0;
    virtual void encode(Encoder& encoder) = 0;
    virtual void restoreXml(class XmlPullParser& parser) = 0;

    static QualifierFilter* restoreFilterXml(class XmlPullParser& parser);
};

} // namespace ghidra
