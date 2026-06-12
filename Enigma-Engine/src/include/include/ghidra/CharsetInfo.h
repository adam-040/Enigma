/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CharsetInfo.h
/// \brief Additional information about a java.nio.charset.Charset that Ghidra
///        needs to be able to create Ghidra string datatype instances.
/// Translated from: ghidra.util.charset.CharsetInfo
#pragma once

#include <set>
#include <string>
#include <vector>

namespace ghidra {

/**
 * Additional information about a charset that Enigma needs to be able to
 * create Ghidra string datatype instances.  Script information is stored as a
 * set of script name strings (a simplified stand-in for Java's
 * java.lang.Character.UnicodeScript enum, which is not ported here).
 *
 * Translated from: ghidra.util.charset.CharsetInfo
 */
class CharsetInfo {
public:
    static const int UNICODESCRIPT_COUNT = 128;

    CharsetInfo();
    CharsetInfo(const std::string& name, const std::string& comment, int minBytesPerChar,
                int maxBytesPerChar, int alignment, int codePointCount,
                bool standardCharset, bool canProduceError,
                const std::set<std::string>& scripts, const std::set<std::string>& contains);

    CharsetInfo withComment(const std::string& newComment) const;

    const std::string& getName() const { return name_; }
    const std::string& getComment() const { return comment_; }
    int getMinBytesPerChar() const { return minBytesPerChar_; }
    int getMaxBytesPerChar() const { return maxBytesPerChar_; }
    int getAlignment() const { return alignment_; }
    int getCodePointCount() const { return codePointCount_; }
    bool isStandardCharset() const { return standardCharset_; }
    bool isCanProduceError() const { return canProduceError_; }
    const std::set<std::string>& getScripts() const { return scripts_; }
    const std::set<std::string>& getContains() const { return contains_; }

    bool supportsAllScripts() const;
    bool hasFixedLengthChars() const;

    std::string getCharsetName() const { return name_; }

    bool operator==(const CharsetInfo& other) const { return name_ == other.name_; }
    bool operator!=(const CharsetInfo& other) const { return name_ != other.name_; }

    size_t hashCode() const;

private:
    std::string name_;
    std::string comment_;
    int minBytesPerChar_;
    int maxBytesPerChar_;
    int alignment_;
    int codePointCount_;
    std::set<std::string> scripts_;
    std::set<std::string> contains_;
    bool canProduceError_;
    bool standardCharset_;
};

} // namespace ghidra
