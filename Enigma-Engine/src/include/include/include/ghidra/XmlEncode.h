/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file XmlEncode.h
/// \brief XML based encoder
#pragma once

#include <ghidra/Encoder.h>
#include <ostream>
#include <vector>

namespace ghidra {

class XmlEncode : public Encoder {
public:
    explicit XmlEncode(std::ostream& out);
    ~XmlEncode() override = default;

    void openElement(const ElementId& elemId) override;
    void closeElement(const ElementId& elemId) override;

    void writeBool(const AttributeId& attribId, bool val) override;
    void writeSignedInteger(const AttributeId& attribId, int64_t val) override;
    void writeUnsignedInteger(const AttributeId& attribId, uint64_t val) override;
    void writeString(const AttributeId& attribId, const std::string& val) override;
    void writeSpace(const AttributeId& attribId, const AddressSpace* spc) override;

private:
    std::ostream& out_;
    std::vector<ElementId> elementStack_;
    bool pendingTagClose_ = false;

    void closePendingTag();
    static std::string escapeXml(const std::string& str, bool isAttribute);
};

} // namespace ghidra
