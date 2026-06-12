/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AndFilter.h
/// \brief Logically AND multiple QualifierFilters together
/// Translated from: ghidra.program.model.lang.protorules.AndFilter
#pragma once

#include <ghidra/QualifierFilter.h>
#include <vector>

namespace ghidra {

class AndFilter : public QualifierFilter {
private:
    std::vector<QualifierFilter*> subQualifiers;

public:
    explicit AndFilter(std::vector<QualifierFilter*>& qualifierList);
    AndFilter(const AndFilter& op);
    ~AndFilter() override;

    AndFilter& operator=(const AndFilter& op) = delete;

    QualifierFilter* clone() const override;
    bool isEquivalent(const QualifierFilter& op) const override;
    bool filter(const PrototypePieces& proto, int pos) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;
};

} // namespace ghidra
