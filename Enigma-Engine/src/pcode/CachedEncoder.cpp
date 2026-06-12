/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CachedEncoder.cpp
/// \brief In-memory CachedEncoder implementation
#include "ghidra/CachedEncoder.h"
#include <ostream>

namespace ghidra {

void MemoryCachedEncoder::writeTo(std::ostream& stream) {
    if (!buffer.empty()) {
        stream.write(reinterpret_cast<const char*>(buffer.data()), (std::streamsize)buffer.size());
    }
    buffer.clear();
    depthStack.clear();
}

void MemoryCachedEncoder::openElement(const ElementId& elemId) {
    buffer.push_back('<');
    for (char c : elemId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('>');
    depthStack.push_back(elemId.id);
}

void MemoryCachedEncoder::closeElement(const ElementId& elemId) {
    buffer.push_back('<');
    buffer.push_back('/');
    for (char c : elemId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('>');
    if (!depthStack.empty()) depthStack.pop_back();
}

void MemoryCachedEncoder::writeBool(const AttributeId& attribId, bool val) {
    buffer.push_back(' ');
    for (char c : attribId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('=');
    const char* v = val ? "true" : "false";
    for (const char* p = v; *p; ++p) buffer.push_back((uint8_t)*p);
    buffer.push_back('"');
    buffer.push_back('"');
}

void MemoryCachedEncoder::writeSignedInteger(const AttributeId& attribId, int64_t val) {
    buffer.push_back(' ');
    for (char c : attribId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('=');
    buffer.push_back('"');
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)val);
    for (int i = 0; i < n; ++i) buffer.push_back((uint8_t)tmp[i]);
    buffer.push_back('"');
}

void MemoryCachedEncoder::writeUnsignedInteger(const AttributeId& attribId, uint64_t val) {
    buffer.push_back(' ');
    for (char c : attribId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('=');
    buffer.push_back('"');
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)val);
    for (int i = 0; i < n; ++i) buffer.push_back((uint8_t)tmp[i]);
    buffer.push_back('"');
}

void MemoryCachedEncoder::writeString(const AttributeId& attribId, const std::string& val) {
    buffer.push_back(' ');
    for (char c : attribId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('=');
    buffer.push_back('"');
    for (char c : val) buffer.push_back((uint8_t)c);
    buffer.push_back('"');
}

void MemoryCachedEncoder::writeSpace(const AttributeId& attribId, const AddressSpace* spc) {
    buffer.push_back(' ');
    for (char c : attribId.name) buffer.push_back((uint8_t)c);
    buffer.push_back('=');
    buffer.push_back('"');
    if (spc != nullptr) {
        for (char c : spc->getName()) buffer.push_back((uint8_t)c);
    }
    buffer.push_back('"');
}

} // namespace ghidra
