/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PositionMatchFilter.h
/// \brief Filter that selects for a particular parameter position
/// Translated from: ghidra.program.model.lang.protorules.PositionMatchFilter
#pragma once

#include <ghidra/QualifierFilter.h>

namespace ghidra {

class PositionMatchFilter : public QualifierFilter {
public:
    explicit PositionMatchFilter(int pos);
    QualifierFilter* clone() const override;
    bool isEquivalent(const QualifierFilter& op) const override;
    bool filter(const PrototypePieces& proto, int pos) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

private:
    int position;
};

} // namespace ghidra
