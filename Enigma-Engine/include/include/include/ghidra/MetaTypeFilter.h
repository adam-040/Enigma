/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MetaTypeFilter.h
/// \brief Filter on a single meta data-type (TYPE_STRUCT, TYPE_FLOAT, etc.)
/// Translated from: ghidra.program.model.lang.protorules.MetaTypeFilter
#pragma once

#include <ghidra/SizeRestrictedFilter.h>

namespace ghidra {

class MetaTypeFilter : public SizeRestrictedFilter {
public:
    MetaTypeFilter(int meta);
    MetaTypeFilter(int meta, int min, int max);
    MetaTypeFilter(const MetaTypeFilter& op2);
    DatatypeFilter* clone() const override;
    bool isEquivalent(const DatatypeFilter& op) const override;
    bool filter(DataType* dt) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

protected:
    void encodeAttributes(Encoder& encoder);

private:
    int metaType;
};

} // namespace ghidra
