/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringIngest.cpp
/// \brief ByteIngest implementation that ingests into an in-memory byte buffer.
#include "ghidra/StringIngest.h"
#include <sstream>
#include <stdexcept>

namespace ghidra {

StringIngest::StringIngest() {
    clear();
}

void StringIngest::open(int max, const std::string& desc) {
    maxBytes_ = max;
    description_ = desc;
    buffer_.clear();
    open_ = true;
}

void StringIngest::ingestStreamToNextTerminator(std::istream& in) {
    if (!open_) throw std::runtime_error("StringIngest not open");
    int tok;
    while ((tok = in.get()) > 0) {
        if (static_cast<int>(buffer_.size()) >= maxBytes_) {
            throw std::runtime_error("Buffer size exceeded: " + description_);
        }
        buffer_.push_back(static_cast<uint8_t>(tok));
    }
}

void StringIngest::ingestStream(std::istream& /*in*/) {
    throw std::runtime_error("Not supported");
}

void StringIngest::ingestBytes(const uint8_t* bytes, int off, int sz) {
    if (!open_) throw std::runtime_error("StringIngest not open");
    for (int i = 0; i < sz; ++i) {
        if (static_cast<int>(buffer_.size()) >= maxBytes_) {
            throw std::runtime_error("Buffer size exceeded: " + description_);
        }
        buffer_.push_back(bytes[off + i]);
    }
}

void StringIngest::endIngest() {
}

void StringIngest::clear() {
    buffer_.clear();
    description_.clear();
    maxBytes_ = 0;
    open_ = false;
}

bool StringIngest::isEmpty() const {
    return buffer_.empty();
}

std::string StringIngest::toString() const {
    if (buffer_.empty()) return "<empty>";
    return std::string(reinterpret_cast<const char*>(buffer_.data()), buffer_.size());
}

std::vector<uint8_t> StringIngest::getBytes() const {
    return buffer_;
}

} // namespace ghidra
