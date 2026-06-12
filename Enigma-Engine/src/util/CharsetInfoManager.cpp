/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CharsetInfoManager.cpp
#include "ghidra/CharsetInfoManager.h"
#include <set>

namespace ghidra {

const std::string CharsetInfoManager::UTF8 = "UTF-8";
const std::string CharsetInfoManager::UTF16 = "UTF-16";
const std::string CharsetInfoManager::UTF32 = "UTF-32";
const std::string CharsetInfoManager::USASCII = "US-ASCII";

std::string CharsetInfoManager::stripCharsetX(const std::string& csName) {
    if (csName.size() >= 2 && csName[0] == 'x' && csName[1] == '-') {
        return csName.substr(2);
    }
    return csName;
}

int CharsetInfoManager::compareCharsetNames(const std::string& s1, const std::string& s2) {
    std::string a = stripCharsetX(s1);
    std::string b = stripCharsetX(s2);
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = static_cast<unsigned char>(std::tolower(a[i]));
        unsigned char cb = static_cast<unsigned char>(std::tolower(b[i]));
        if (ca != cb) {
            return static_cast<int>(ca) - static_cast<int>(cb);
        }
    }
    return static_cast<int>(a.size()) - static_cast<int>(b.size());
}

int CharsetInfoManager::compareCharsetInfos(const CharsetInfo& csi1, const CharsetInfo& csi2) {
    return compareCharsetNames(csi1.getName(), csi2.getName());
}

CharsetInfoManager& CharsetInfoManager::getInstance() {
    static CharsetInfoManager instance;
    return instance;
}

bool CharsetInfoManager::isBOMCharset(const std::string& charsetName) {
    return charsetName == UTF32 || charsetName == UTF16;
}

std::vector<std::string> CharsetInfoManager::getStandardCharsetNames() {
    return {USASCII, UTF8, UTF16, UTF32};
}

namespace {
const std::string COMMON_SCRIPT = "COMMON";
const std::string LATIN_SCRIPT = "LATIN";

std::set<std::string> allScripts() {
    return {};
}
}

CharsetInfoManager::CharsetInfoManager() {
    charsets_.push_back(CharsetInfo(USASCII, std::string(), 1, 1, 1, -1, true, true,
                                    {COMMON_SCRIPT, LATIN_SCRIPT}, {}));
    charsets_.push_back(CharsetInfo(UTF8, std::string(), 1, 4, 1, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo(UTF16, std::string(), 2, 4, 2, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo("UTF-16BE", std::string(), 2, 4, 2, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo("UTF-16LE", std::string(), 2, 4, 2, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo(UTF32, std::string(), 4, 4, 4, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo("UTF-32BE", std::string(), 4, 4, 4, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo("UTF-32LE", std::string(), 4, 4, 4, -1, true, true,
                                    allScripts(), {}));
    charsets_.push_back(CharsetInfo("ISO-8859-1", std::string(), 1, 1, 1, -1, true, false,
                                    {COMMON_SCRIPT, LATIN_SCRIPT}, {USASCII}));

    for (const auto& csi : charsets_) {
        charsetNames_.push_back(csi.getName());
    }
    for (size_t i = 0; i < charsetNames_.size(); ++i) {
        nameIndex_[charsetNames_[i]] = i;
    }
}

CharsetInfoManager::CharsetInfoManager(const std::vector<CharsetInfo>& userDefinedInfo) {
    (void)userDefinedInfo;
    *this = CharsetInfoManager();
}

std::vector<CharsetInfo> CharsetInfoManager::getCharsets() const {
    return charsets_;
}

int CharsetInfoManager::getCharsetCharSize(const std::string& charsetName) const {
    auto it = nameIndex_.find(charsetName);
    if (it != nameIndex_.end()) {
        return charsets_[it->second].getMinBytesPerChar();
    }
    return 1;
}

std::vector<std::string> CharsetInfoManager::getCharsetNamesWithCharSize(int size) const {
    std::vector<std::string> result;
    for (const auto& csi : charsets_) {
        if (csi.getMinBytesPerChar() == size) {
            result.push_back(csi.getName());
        }
    }
    return result;
}

const CharsetInfo* CharsetInfoManager::get(const std::string& name) const {
    auto it = nameIndex_.find(name);
    if (it != nameIndex_.end()) {
        return &charsets_[it->second];
    }
    return nullptr;
}

const CharsetInfo* CharsetInfoManager::get(const std::string& name,
                                            const std::string& defaultCS) const {
    const CharsetInfo* result = get(name);
    if (result == nullptr && !defaultCS.empty()) {
        result = get(defaultCS);
    }
    return result;
}

void CharsetInfoManager::reinitializeWithUserDefinedCharsets() {
}

} // namespace ghidra
