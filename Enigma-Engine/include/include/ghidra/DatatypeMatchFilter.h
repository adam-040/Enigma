/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DatatypeMatchFilter.h
/// \brief Check if the function signature has a specific data-type at a specific position
/// Translated from: ghidra.program.model.lang.protorules.DatatypeMatchFilter
#pragma once

#include <ghidra/QualifierFilter.h>
#include <ghidra/DatatypeFilter.h>

namespace ghidra {

class DatatypeMatchFilter : public QualifierFilter {
public:
    DatatypeMatchFilter();
    ~DatatypeMatchFilter() override;
    QualifierFilter* clone() const override;
    bool isEquivalent(const QualifierFilter& op) const override;
    bool filter(const PrototypePieces& proto, int pos) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    int position;
    DatatypeFilter* typeFilter;
};

} // namespace ghidra
