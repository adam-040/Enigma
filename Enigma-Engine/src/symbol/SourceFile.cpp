/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceFile.cpp
/// \brief Immutable source-file descriptor.
#include "ghidra/SourceFile.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace ghidra {

namespace {
std::string toHex(const std::vector<uint8_t>& bytes) {
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(hx[(b >> 4) & 0xf]);
        out.push_back(hx[b & 0xf]);
    }
    return out;
}
}

SourceFile::SourceFile(const std::string& path)
    : SourceFile(path, SourceFileIdType::NONE, {}, true) {}

SourceFile::SourceFile(const std::string& path, SourceFileIdType type,
                       const std::vector<uint8_t>& identifier)
    : SourceFile(path, type, identifier, true) {}

SourceFile::SourceFile(const std::string& path, SourceFileIdType type,
                       const std::vector<uint8_t>& identifier, bool validate)
    : idType_(type) {
    if (validate) {
        if (path.empty()) {
            throw std::invalid_argument("SourceFile path cannot be null or blank");
        }
        if (path.find("..") != std::string::npos) {
            throw std::invalid_argument("SourceFile path must be absolute after normalization");
        }
        if (path.back() == '/') {
            throw std::invalid_argument("SourceFile URI must represent a file (not a directory)");
        }
    }
    path_ = path;
    auto pos = path_.find_last_of('/');
    filename_ = (pos == std::string::npos) ? path_ : path_.substr(pos + 1);
    identifier_ = validateAndCopyIdentifier(identifier);
    computeDerived();
}

void SourceFile::computeDerived() {
    int h = 0;
    for (char c : path_) h = h * 31 + static_cast<int>(c);
    h = h * 31 + static_cast<int>(idType_);
    for (auto b : identifier_) h = h * 31 + b;
    hash_ = h;
    idDisplayString_ = computeIdDisplayString();
}

std::vector<uint8_t> SourceFile::getIdentifier() const {
    return identifier_;
}

std::string SourceFile::getIdAsString() const {
    return idDisplayString_;
}

int SourceFile::compareTo(const SourceFile& other) const {
    if (path_ != other.path_) return path_ < other.path_ ? -1 : 1;
    if (idType_ != other.idType_) return idType_ < other.idType_ ? -1 : 1;
    if (identifier_ < other.identifier_) return -1;
    if (identifier_ > other.identifier_) return 1;
    return 0;
}

bool SourceFile::equals(const SourceFile& other) const {
    return path_ == other.path_ && idType_ == other.idType_ && identifier_ == other.identifier_;
}

std::string SourceFile::toString() const {
    std::ostringstream sb;
    sb << path_;
    if (idType_ == SourceFileIdType::NONE) return sb.str();
    sb << " [" << ghidra::toString(idType_) << "=" << idDisplayString_ << "]";
    return sb.str();
}

std::vector<uint8_t> SourceFile::validateAndCopyIdentifier(const std::vector<uint8_t>& array) {
    if (idType_ == SourceFileIdType::NONE || array.empty()) {
        return {};
    }
    return array;
}

std::string SourceFile::computeIdDisplayString() const {
    if (idType_ == SourceFileIdType::NONE) return "";
    if (idType_ == SourceFileIdType::TIMESTAMP_64 && identifier_.size() >= 8) {
        int64_t v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | identifier_[i];
        return std::to_string(v);
    }
    return toHex(identifier_);
}

} // namespace ghidra
