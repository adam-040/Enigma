/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CharsetInfo.cpp
#include "ghidra/CharsetInfo.h"
#include <functional>

namespace ghidra {

CharsetInfo::CharsetInfo()
    : name_(), comment_(), minBytesPerChar_(1), maxBytesPerChar_(-1), alignment_(1),
      codePointCount_(-1), canProduceError_(false), standardCharset_(true) {}

CharsetInfo::CharsetInfo(const std::string& name, const std::string& comment,
                          int minBytesPerChar, int maxBytesPerChar, int alignment,
                          int codePointCount, bool standardCharset, bool canProduceError,
                          const std::set<std::string>& scripts,
                          const std::set<std::string>& contains)
    : name_(name), comment_(comment), minBytesPerChar_(minBytesPerChar),
      maxBytesPerChar_(maxBytesPerChar), alignment_(alignment), codePointCount_(codePointCount),
      scripts_(scripts), contains_(contains), canProduceError_(canProduceError),
      standardCharset_(standardCharset) {}

CharsetInfo CharsetInfo::withComment(const std::string& newComment) const {
    return CharsetInfo(name_, newComment, minBytesPerChar_, maxBytesPerChar_, alignment_,
                       codePointCount_, standardCharset_, canProduceError_, scripts_,
                       contains_);
}

bool CharsetInfo::supportsAllScripts() const {
    return static_cast<int>(scripts_.size()) >= UNICODESCRIPT_COUNT - 1;
}

bool CharsetInfo::hasFixedLengthChars() const {
    return minBytesPerChar_ > 0 && minBytesPerChar_ == maxBytesPerChar_;
}

size_t CharsetInfo::hashCode() const {
    return std::hash<std::string>{}(name_);
}

} // namespace ghidra
