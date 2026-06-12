/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HomogeneousAggregate.h
/// \brief Filter on a homogeneous aggregate data-type
/// Translated from: ghidra.program.model.lang.protorules.HomogeneousAggregate
#pragma once

#include <ghidra/SizeRestrictedFilter.h>
#include <string>

namespace ghidra {

class HomogeneousAggregate : public SizeRestrictedFilter {
public:
    static constexpr const char* NAME_FLOAT = "homogeneous-float-aggregate";
    static constexpr int DEFAULT_MAX_PRIMITIVES = 4;

    HomogeneousAggregate(const std::string& nm, int meta);
    HomogeneousAggregate(const std::string& nm, int meta, int maxPrim, int minSize, int maxSize);
    HomogeneousAggregate(const HomogeneousAggregate& op2);

    DatatypeFilter* clone() const override;
    bool isEquivalent(const DatatypeFilter& op) const override;
    bool filter(DataType* dt) override;
    void encode(Encoder& encoder) override;
    void restoreXml(class XmlPullParser& parser) override;

protected:
    void encodeAttributes(Encoder& encoder) override;
    void restoreAttributesXml(class XmlElement* el) override;

private:
    std::string name;
    int metaType;
    int maxPrimitives;
};

} // namespace ghidra
