/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SizeRestrictedFilter.h
/// \brief DatatypeFilter that restricts by min/max size or an enumerated list of sizes
/// Translated from: ghidra.program.model.lang.protorules.SizeRestrictedFilter
#pragma once

#include <ghidra/DatatypeFilter.h>
#include <unordered_set>
#include <string>

namespace ghidra {

class XmlElement;

class SizeRestrictedFilter : public DatatypeFilter {
public:
    static constexpr const char* NAME = "any";

    int minSize = 0;
    int maxSize = 0;
    std::unordered_set<int> sizes;

    SizeRestrictedFilter() = default;
    explicit SizeRestrictedFilter(int min, int max);
    SizeRestrictedFilter(const SizeRestrictedFilter& op2);

    DatatypeFilter* clone() const override;
    bool isEquivalent(const DatatypeFilter& op) const override;
    bool filter(DataType* dt) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

    bool filterOnSize(DataType* dt) const;

    void initFromSizeList(const std::string& str);

protected:
    virtual void encodeAttributes(Encoder& encoder);
    virtual void restoreAttributesXml(class XmlElement* el);
};

} // namespace ghidra
