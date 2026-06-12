/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CharsetInfoManager.h
/// \brief Maintains a list of charsets and info about each charset.
/// Translated from: ghidra.util.charset.CharsetInfoManager
#pragma once

#include "CharsetInfo.h"
#include <algorithm>
#include <cctype>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ghidra {

/**
 * Maintains a list of charsets and info about each charset.  More common
 * charsets are ordered toward the beginning of the list.
 *
 * The singleton instance only contains generic JVM information.  The
 * user-defined charsets from the Ghidra charset_info.json config file are not
 * loaded here (no Ghidra Application equivalent in the CLI), but the
 * infrastructure for re-initialization is in place.
 *
 * Translated from: ghidra.util.charset.CharsetInfoManager
 */
class CharsetInfoManager {
public:
    static const std::string UTF8;
    static const std::string UTF16;
    static const std::string UTF32;
    static const std::string USASCII;

    static int compareCharsetNames(const std::string& s1, const std::string& s2);
    static int compareCharsetInfos(const CharsetInfo& csi1, const CharsetInfo& csi2);

    static CharsetInfoManager& getInstance();
    static bool isBOMCharset(const std::string& charsetName);
    static std::vector<std::string> getStandardCharsetNames();
    static void reinitializeWithUserDefinedCharsets();

    const std::vector<std::string>& getCharsetNames() const { return charsetNames_; }
    std::vector<CharsetInfo> getCharsets() const;

    int getCharsetCharSize(const std::string& charsetName) const;
    std::vector<std::string> getCharsetNamesWithCharSize(int size) const;
    const CharsetInfo* get(const std::string& name) const;
    const CharsetInfo* get(const std::string& name, const std::string& defaultCS) const;

private:
    CharsetInfoManager();
    CharsetInfoManager(const std::vector<CharsetInfo>& userDefinedInfo);

    static std::string stripCharsetX(const std::string& csName);

    std::vector<CharsetInfo> charsets_;
    std::vector<std::string> charsetNames_;
    std::unordered_map<std::string, size_t> nameIndex_;
};

} // namespace ghidra
