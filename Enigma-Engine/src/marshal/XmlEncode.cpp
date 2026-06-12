/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file XmlEncode.cpp
/// \brief XML based encoder implementation
#include "ghidra/XmlEncode.h"
#include <iomanip>

namespace ghidra {

XmlEncode::XmlEncode(std::ostream& out) : out_(out) {}

void XmlEncode::closePendingTag() {
    if (pendingTagClose_) {
        out_ << ">";
        pendingTagClose_ = false;
    }
}

void XmlEncode::openElement(const ElementId& elemId) {
    closePendingTag();
    out_ << "<" << elemId.name;
    elementStack_.push_back(elemId);
    pendingTagClose_ = true;
}

void XmlEncode::closeElement(const ElementId& elemId) {
    if (elementStack_.empty()) {
        return;
    }
    ElementId top = elementStack_.back();
    elementStack_.pop_back();

    if (pendingTagClose_) {
        out_ << "/>";
        pendingTagClose_ = false;
    } else {
        out_ << "</" << top.name << ">";
    }
}

void XmlEncode::writeBool(const AttributeId& attribId, bool val) {
    if (attribId.id == ATTRIB_CONTENT.id) {
        closePendingTag();
        out_ << (val ? "true" : "false");
    } else if (pendingTagClose_) {
        out_ << " " << attribId.name << "=\"" << (val ? "true" : "false") << "\"";
    }
}

void XmlEncode::writeSignedInteger(const AttributeId& attribId, int64_t val) {
    if (attribId.id == ATTRIB_CONTENT.id) {
        closePendingTag();
        out_ << val;
    } else if (pendingTagClose_) {
        out_ << " " << attribId.name << "=\"" << val << "\"";
    }
}

void XmlEncode::writeUnsignedInteger(const AttributeId& attribId, uint64_t val) {
    if (attribId.id == ATTRIB_CONTENT.id) {
        closePendingTag();
        out_ << "0x" << std::hex << val << std::dec;
    } else if (pendingTagClose_) {
        out_ << " " << attribId.name << "=\"0x" << std::hex << val << std::dec << "\"";
    }
}

void XmlEncode::writeString(const AttributeId& attribId, const std::string& val) {
    if (attribId.id == ATTRIB_CONTENT.id) {
        closePendingTag();
        out_ << escapeXml(val, false);
    } else if (pendingTagClose_) {
        out_ << " " << attribId.name << "=\"" << escapeXml(val, true) << "\"";
    }
}

void XmlEncode::writeSpace(const AttributeId& attribId, const AddressSpace* spc) {
    if (spc) {
        writeString(attribId, spc->getName());
    }
}

std::string XmlEncode::escapeXml(const std::string& str, bool isAttribute) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        if (c == '&') result += "&amp;";
        else if (c == '<') result += "&lt;";
        else if (c == '>') result += "&gt;";
        else if (isAttribute && c == '"') result += "&quot;";
        else if (isAttribute && c == '\'') result += "&apos;";
        else result += c;
    }
    return result;
}

} // namespace ghidra
