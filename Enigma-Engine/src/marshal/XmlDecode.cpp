/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file XmlDecode.cpp
/// \brief XML based decoder implementation
#include "ghidra/XmlDecode.h"
#include <iostream>

namespace ghidra {

XmlDecode::XmlDecode() {}

XmlDecode::XmlDecode(AddressFactory* addrFactory) : addrFactory_(addrFactory) {}

void XmlDecode::ingestStream(std::istream& s) {
    std::string str((std::istreambuf_iterator<char>(s)), std::istreambuf_iterator<char>());
    ingestString(str);
}

void XmlDecode::ingestString(const std::string& s) {
    parser_ = XmlPullParser(s);
    stack_.clear();
}

int XmlDecode::peekElement() {
    XmlPullParser temp = parser_;
    if (!temp.hasNext()) return 0;
    XmlElement elem = temp.nextElement();
    if (elem.isEnd()) {
        return 0; // End of current element's children
    }
    return resolveElementId(elem.getName());
}

int XmlDecode::openElement() {
    if (!parser_.hasNext()) {
        throw DecoderException("Unexpected end of XML stream");
    }
    XmlElement elem = parser_.nextElement();
    if (elem.isEnd()) {
        throw DecoderException("Expected start element, found end element: " + elem.getName());
    }

    ElementFrame frame;
    frame.element = elem;
    frame.elementId = resolveElementId(elem.getName());
    for (const auto& pair : elem.getAttributes()) {
        frame.attribKeys.push_back(pair.first);
    }
    frame.attribIndex = 0;
    frame.currentAttribKey = "";

    stack_.push_back(frame);
    return frame.elementId;
}

int XmlDecode::openElement(const ElementId& elemId) {
    if (!parser_.hasNext()) {
        throw DecoderException("Unexpected end of XML stream, expected: " + elemId.name);
    }
    XmlElement elem = parser_.nextElement();
    if (elem.isEnd()) {
        throw DecoderException("Expected start element " + elemId.name + ", found end element: " + elem.getName());
    }
    if (elem.getName() != elemId.name) {
        throw DecoderException("Expected start element " + elemId.name + ", found: " + elem.getName());
    }

    ElementFrame frame;
    frame.element = elem;
    frame.elementId = elemId.id;
    for (const auto& pair : elem.getAttributes()) {
        frame.attribKeys.push_back(pair.first);
    }
    frame.attribIndex = 0;
    frame.currentAttribKey = "";

    stack_.push_back(frame);
    return frame.elementId;
}

void XmlDecode::closeElement() {
    if (!parser_.hasNext()) {
        throw DecoderException("Unexpected end of XML stream on closeElement");
    }
    XmlElement elem = parser_.nextElement();
    if (!elem.isEnd()) {
        throw DecoderException("Expected end element, found start element: " + elem.getName());
    }
    if (stack_.empty()) {
        throw DecoderException("Element stack underflow on closeElement");
    }
    stack_.pop_back();
}

void XmlDecode::closeElement(int id) {
    if (!parser_.hasNext()) {
        throw DecoderException("Unexpected end of XML stream on closeElement");
    }
    XmlElement elem = parser_.nextElement();
    if (!elem.isEnd()) {
        throw DecoderException("Expected end element, found start element: " + elem.getName());
    }
    int resolvedId = resolveElementId(elem.getName());
    if (resolvedId != id) {
        throw DecoderException("Expected end element ID " + std::to_string(id) + ", found: " + elem.getName());
    }
    if (stack_.empty()) {
        throw DecoderException("Element stack underflow on closeElement");
    }
    stack_.pop_back();
}

int XmlDecode::getNextAttributeId() {
    if (stack_.empty()) return 0;
    ElementFrame& frame = stack_.back();
    if (frame.attribIndex < frame.attribKeys.size()) {
        frame.currentAttribKey = frame.attribKeys[frame.attribIndex++];
        return resolveAttributeId(frame.currentAttribKey);
    }
    return 0;
}

bool XmlDecode::readBool() {
    if (stack_.empty()) throw DecoderException("No active element for readBool");
    const ElementFrame& frame = stack_.back();
    if (frame.currentAttribKey.empty()) throw DecoderException("No active attribute for readBool");
    std::string val = frame.element.getAttribute(frame.currentAttribKey);
    return (val == "true" || val == "1");
}

int64_t XmlDecode::readSignedInteger() {
    if (stack_.empty()) throw DecoderException("No active element for readSignedInteger");
    const ElementFrame& frame = stack_.back();
    if (frame.currentAttribKey.empty()) throw DecoderException("No active attribute for readSignedInteger");
    std::string val = frame.element.getAttribute(frame.currentAttribKey);
    return static_cast<int>(parseInteger(val));
}

uint64_t XmlDecode::readUnsignedInteger() {
    if (stack_.empty()) throw DecoderException("No active element for readUnsignedInteger");
    const ElementFrame& frame = stack_.back();
    if (frame.currentAttribKey.empty()) throw DecoderException("No active attribute for readUnsignedInteger");
    std::string val = frame.element.getAttribute(frame.currentAttribKey);
    return parseInteger(val);
}

std::string XmlDecode::readString() {
    if (stack_.empty()) throw DecoderException("No active element for readString");
    const ElementFrame& frame = stack_.back();
    if (frame.currentAttribKey.empty()) throw DecoderException("No active attribute for readString");
    return frame.element.getAttribute(frame.currentAttribKey);
}

std::string XmlDecode::readString(int id) {
    if (stack_.empty()) throw DecoderException("No active element for readString");
    const ElementFrame& frame = stack_.back();
    if (id == ATTRIB_CONTENT.id) {
        return frame.element.getText();
    }
    // Search for attribute by ID
    for (const auto& pair : frame.element.getAttributes()) {
        if (resolveAttributeId(pair.first) == id) {
            return pair.second;
        }
    }
    throw DecoderException("Attribute ID " + std::to_string(id) + " not found in element " + frame.element.getName());
}

uint64_t XmlDecode::readUnsignedInteger(int id) {
    std::string val = readString(id);
    return parseInteger(val);
}

int64_t XmlDecode::readSignedInteger(int id) {
    std::string val = readString(id);
    return static_cast<int>(parseInteger(val));
}

bool XmlDecode::readBool(int id) {
    std::string val = readString(id);
    return (val == "true" || val == "1");
}

bool XmlDecode::readBool(AttributeId id) {
    return readBool(id.id);
}

uint64_t XmlDecode::readUnsignedInteger(AttributeId id) {
    return readUnsignedInteger(id.id);
}

int64_t XmlDecode::readSignedInteger(AttributeId id) {
    return readSignedInteger(id.id);
}

std::string XmlDecode::readString(AttributeId id) {
    return readString(id.id);
}

AddressSpace* XmlDecode::readSpace() {
    if (stack_.empty()) throw DecoderException("No active element for readSpace");
    const ElementFrame& frame = stack_.back();
    if (frame.currentAttribKey.empty()) throw DecoderException("No active attribute for readSpace");
    std::string val = frame.element.getAttribute(frame.currentAttribKey);
    if (!addrFactory_) {
        throw DecoderException("AddressFactory not set on Decoder");
    }
    const AddressSpace* spc = addrFactory_->getAddressSpace(val);
    if (!spc) {
        throw DecoderException("Unknown address space: " + val);
    }
    return const_cast<AddressSpace*>(spc);
}

AddressSpace* XmlDecode::readSpace(const AttributeId& attribId) {
    std::string val = readString(attribId.id);
    if (!addrFactory_) {
        throw DecoderException("AddressFactory not set on Decoder");
    }
    const AddressSpace* spc = addrFactory_->getAddressSpace(val);
    if (!spc) {
        throw DecoderException("Unknown address space: " + val);
    }
    return const_cast<AddressSpace*>(spc);
}

int XmlDecode::resolveElementId(const std::string& name) {
    static const std::unordered_map<std::string, int> elemMap = {
        {"rangelist", ELEM_RANGELIST.id},
        {"range", ELEM_RANGE.id},
        {"data", ELEM_DATA.id},
        {"input", ELEM_INPUT.id},
        {"off", ELEM_OFF.id},
        {"output", ELEM_OUTPUT.id},
        {"returnaddress", ELEM_RETURNADDRESS.id},
        {"symbol", ELEM_SYMBOL.id},
        {"target", ELEM_TARGET.id},
        {"val", ELEM_VAL.id},
        {"value", ELEM_VALUE.id},
        {"void", ELEM_VOID.id},
        {"userop", ELEM_USEROP.id},
        {"userop_head", ELEM_USEROP_HEAD.id},
        {"XMLunknown", ELEM_UNKNOWN.id}
    };
    auto it = elemMap.find(name);
    return (it != elemMap.end()) ? it->second : ELEM_UNKNOWN.id;
}

int XmlDecode::resolveAttributeId(const std::string& name) {
    static const std::unordered_map<std::string, int> attrMap = {
        {"XMLcontent", ATTRIB_CONTENT.id},
        {"align", ATTRIB_ALIGN.id},
        {"bigendian", ATTRIB_BIGENDIAN.id},
        {"constructor", ATTRIB_CONSTRUCTOR.id},
        {"destructor", ATTRIB_DESTRUCTOR.id},
        {"extrapop", ATTRIB_EXTRAPOP.id},
        {"format", ATTRIB_FORMAT.id},
        {"hiddenretparm", ATTRIB_HIDDENRETPARM.id},
        {"id", ATTRIB_ID.id},
        {"index", ATTRIB_INDEX.id},
        {"indirectstorage", ATTRIB_INDIRECTSTORAGE.id},
        {"metatype", ATTRIB_METATYPE.id},
        {"model", ATTRIB_MODEL.id},
        {"name", ATTRIB_NAME.id},
        {"namelock", ATTRIB_NAMELOCK.id},
        {"offset", ATTRIB_OFFSET.id},
        {"readonly", ATTRIB_READONLY.id},
        {"ref", ATTRIB_REF.id},
        {"size", ATTRIB_SIZE.id},
        {"space", ATTRIB_SPACE.id},
        {"thisptr", ATTRIB_THISPTR.id},
        {"type", ATTRIB_TYPE.id},
        {"typelock", ATTRIB_TYPELOCK.id},
        {"val", ATTRIB_VAL.id},
        {"value", ATTRIB_VALUE.id},
        {"wordsize", ATTRIB_WORDSIZE.id},
        {"first", ATTRIB_FIRST.id},
        {"last", ATTRIB_LAST.id},
        {"uniq", ATTRIB_UNIQ.id},
        {"addrtied", ATTRIB_ADDRTIED.id},
        {"grp", ATTRIB_GRP.id},
        {"input", ATTRIB_INPUT.id},
        {"persists", ATTRIB_PERSISTS.id},
        {"unaff", ATTRIB_UNAFF.id},
        {"blockref", ATTRIB_BLOCKREF.id},
        {"close", ATTRIB_CLOSE.id},
        {"color", ATTRIB_COLOR.id},
        {"indent", ATTRIB_INDENT.id},
        {"off", ATTRIB_OFF.id},
        {"open", ATTRIB_OPEN.id},
        {"opref", ATTRIB_OPREF.id},
        {"varref", ATTRIB_VARREF.id},
        {"code", ATTRIB_CODE.id},
        {"contain", ATTRIB_CONTAIN.id},
        {"defaultspace", ATTRIB_DEFAULTSPACE.id},
        {"uniqbase", ATTRIB_UNIQBASE.id},
        {"alignment", ATTRIB_ALIGNMENT.id},
        {"arraysize", ATTRIB_ARRAYSIZE.id},
        {"char", ATTRIB_CHAR.id},
        {"core", ATTRIB_CORE.id},
        {"incomplete", ATTRIB_INCOMPLETE.id},
        {"opaquestring", ATTRIB_OPAQUESTRING.id},
        {"signed", ATTRIB_SIGNED.id},
        {"structalign", ATTRIB_STRUCTALIGN.id},
        {"utf", ATTRIB_UTF.id},
        {"varlength", ATTRIB_VARLENGTH.id},
        {"cat", ATTRIB_CAT.id},
        {"field", ATTRIB_FIELD.id},
        {"merge", ATTRIB_MERGE.id},
        {"scope", ATTRIB_SCOPE.id},
        {"scopeidbyname", ATTRIB_SCOPEIDBYNAME.id},
        {"volatile", ATTRIB_VOLATILE.id},
        {"class", ATTRIB_CLASS.id},
        {"repref", ATTRIB_REPREF.id},
        {"symref", ATTRIB_SYMREF.id},
        {"trunc", ATTRIB_TRUNC.id},
        {"dynamic", ATTRIB_DYNAMIC.id},
        {"incidentalcopy", ATTRIB_INCIDENTALCOPY.id},
        {"inject", ATTRIB_INJECT.id},
        {"paramshift", ATTRIB_PARAMSHIFT.id},
        {"targetop", ATTRIB_TARGETOP.id},
        {"altindex", ATTRIB_ALTINDEX.id},
        {"depth", ATTRIB_DEPTH.id},
        {"end", ATTRIB_END.id},
        {"opcode", ATTRIB_OPCODE.id},
        {"rev", ATTRIB_REV.id},
        {"a", ATTRIB_A.id},
        {"b", ATTRIB_B.id},
        {"length", ATTRIB_LENGTH.id},
        {"tag", ATTRIB_TAG.id},
        {"nocode", ATTRIB_NOCODE.id},
        {"farpointer", ATTRIB_FARPOINTER.id},
        {"inputop", ATTRIB_INPUTOP.id},
        {"outputop", ATTRIB_OUTPUTOP.id},
        {"userop", ATTRIB_USEROP.id},
        {"base", ATTRIB_BASE.id},
        {"delay", ATTRIB_DELAY.id},
        {"logicalsize", ATTRIB_LOGICALSIZE.id},
        {"physical", ATTRIB_PHYSICAL.id},
        {"piece", ATTRIB_PIECE.id},
        {"adjustvma", ATTRIB_ADJUSTVMA.id},
        {"enable", ATTRIB_ENABLE.id},
        {"group", ATTRIB_GROUP.id},
        {"growth", ATTRIB_GROWTH.id},
        {"key", ATTRIB_KEY.id},
        {"loadersymbols", ATTRIB_LOADERSYMBOLS.id},
        {"parent", ATTRIB_PARENT.id},
        {"register", ATTRIB_REGISTER.id},
        {"reversejustify", ATTRIB_REVERSEJUSTIFY.id},
        {"signext", ATTRIB_SIGNEXT.id},
        {"style", ATTRIB_STYLE.id},
        {"custom", ATTRIB_CUSTOM.id},
        {"dotdotdot", ATTRIB_DOTDOTDOT.id},
        {"extension", ATTRIB_EXTENSION.id},
        {"hasthis", ATTRIB_HASTHIS.id},
        {"inline", ATTRIB_INLINE.id},
        {"killedbycall", ATTRIB_KILLEDBYCALL.id},
        {"maxsize", ATTRIB_MAXSIZE.id},
        {"minsize", ATTRIB_MINSIZE.id},
        {"modellock", ATTRIB_MODELLOCK.id},
        {"noreturn", ATTRIB_NORETURN.id},
        {"pointermax", ATTRIB_POINTERMAX.id},
        {"separatefloat", ATTRIB_SEPARATEFLOAT.id},
        {"stackshift", ATTRIB_STACKSHIFT.id},
        {"strategy", ATTRIB_STRATEGY.id},
        {"thisbeforeretpointer", ATTRIB_THISBEFORERETPOINTER.id},
        {"voidlock", ATTRIB_VOIDLOCK.id},
        {"vector_lane_sizes", ATTRIB_VECTOR_LANE_SIZES.id},
        {"label", ATTRIB_LABEL.id},
        {"num", ATTRIB_NUM.id},
        {"lock", ATTRIB_LOCK.id},
        {"main", ATTRIB_MAIN.id},
        {"baddata", ATTRIB_BADDATA.id},
        {"hash", ATTRIB_HASH.id},
        {"unimpl", ATTRIB_UNIMPL.id},
        {"storage", ATTRIB_STORAGE.id},
        {"stackspill", ATTRIB_STACKSPILL.id},
        {"sizes", ATTRIB_SIZES.id},
        {"backfill", ATTRIB_BACKFILL.id},
        {"maxprimitives", ATTRIB_MAX_PRIMITIVES.id},
        {"reversesignif", ATTRIB_REVERSESIGNIF.id},
        {"matchsize", ATTRIB_MATCHSIZE.id},
        {"afterbytes", ATTRIB_AFTER_BYTES.id},
        {"afterstorage", ATTRIB_AFTER_STORAGE.id},
        {"fillalternate", ATTRIB_FILL_ALTERNATE.id}
    };
    auto it = attrMap.find(name);
    return (it != attrMap.end()) ? it->second : ATTRIB_UNKNOWN.id;
}

uint64_t XmlDecode::parseInteger(const std::string& val) {
    if (val.empty()) return 0;
    try {
        return std::stoull(val, nullptr, 0);
    } catch (...) {
        try {
            return static_cast<uint64_t>(std::stoll(val, nullptr, 0));
        } catch (...) {
            return 0;
        }
    }
}

void XmlDecode::skipElement() {
    if (!parser_.hasNext()) return;
    XmlElement elem = parser_.nextElement();
    if (elem.isEnd()) {
        // Already at end of current element
        return;
    }
    // Skip all children until we find matching end element
    int depth = 1;
    while (depth > 0 && parser_.hasNext()) {
        elem = parser_.nextElement();
        if (elem.isEnd())
            depth--;
        else
            depth++;
    }
    if (!stack_.empty())
        stack_.pop_back();
}

void XmlDecode::rewindAttributes() {
    if (stack_.empty()) return;
    ElementFrame& frame = stack_.back();
    frame.attribIndex = 0;
    frame.currentAttribKey = "";
}

} // namespace ghidra
