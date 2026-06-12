/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringDataInstance.cpp
#include "ghidra/StringDataInstance.h"
#include "ghidra/AbstractStringDataType.h"
#include "ghidra/ArrayStringable.h"
#include "ghidra/CharsetInfoManager.h"
#include "ghidra/DataType.h"
#include "ghidra/DataTypeWithCharset.h"
#include "ghidra/DataTypeDisplayOptions.h"
#include "ghidra/EndianSettingsDefinition.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/NoSettings.h"
#include "ghidra/Settings.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>

namespace ghidra {

const std::string StringDataInstance::DEFAULT_CHARSET_NAME = "US-ASCII";
const std::string StringDataInstance::UNKNOWN = "??";
const std::string StringDataInstance::UNKNOWN_DOT_DOT_DOT = "??...";

namespace {
const int UNICODE_BE_BYTE_ORDER_MARK = 0xFEFF;
const int UNICODE_LE16_BYTE_ORDER_MARK = 0xFFFE;
const int UNICODE_LE32_BYTE_ORDER_MARK = 0xFFFE0000;

bool isDisplayable(int codePoint) {
    if (codePoint < 0x20) {
        return codePoint == '\t' || codePoint == '\n' || codePoint == '\r';
    }
    if (codePoint < 0x7F) return true;
    if (codePoint >= 0x80 && codePoint <= 0xFF) return true;
    if (codePoint == 0x9F) return true;
    return codePoint >= 0xA0;
}

std::string toLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return r;
}
} // namespace

StringDataInstance::StringDataInstance(DataType* dataType, Settings* settings, MemBuffer* buf,
                                        int length)
    : StringDataInstance(dataType, settings, buf, length, false) {}

StringDataInstance::StringDataInstance(DataType* dataType, Settings* settings, MemBuffer* buf,
                                        int length, bool isArrayElement) {
    if (settings == nullptr) {
        settings = &NoSettings::instance();
    }
    buf_ = buf;
    charsetName_ = getCharsetNameFromDataTypeOrSettings(dataType, settings);
    charSize_ = CharsetInfoManager::getInstance().getCharsetCharSize(charsetName_);
    paddedCharSize_ = (dynamic_cast<ArrayStringable*>(dataType) != nullptr && charSize_ == 1)
                          ? charSize_
                          : charSize_;
    (void)paddedCharSize_;
    paddedCharSize_ = charSize_;
    stringLayout_ = isArrayElement ? StringLayoutEnum::NULL_TERMINATED_BOUNDED
                                    : StringLayoutEnum::FIXED_LEN;
    if (dataType != nullptr) {
        AbstractStringDataType* asdt = dynamic_cast<AbstractStringDataType*>(dataType);
        if (asdt != nullptr) {
            stringLayout_ = asdt->getStringLayout();
        }
    }
    showTranslation_ = TranslationSettingsDefinition::def().isShowTranslated(settings);
    translatedValue_ = std::string();
    renderSetting_ = RenderUnicodeSettingsDefinition::def().getEnumValue(settings);
    endianSetting_ = EndianSettingsDefinition::def().getEndianness(settings, Endian::LITTLE);
    length_ = length;
}

StringDataInstance::StringDataInstance(const StringDataInstance& copyFrom,
                                        StringLayoutEnum newLayout, MemBuffer* newBuf,
                                        int newLen, const std::string& newCharsetName)
    : charsetName_(newCharsetName), charSize_(copyFrom.charSize_),
      paddedCharSize_(copyFrom.paddedCharSize_), stringLayout_(newLayout),
      translatedValue_(), endianSetting_(copyFrom.endianSetting_),
      showTranslation_(false), renderSetting_(copyFrom.renderSetting_), length_(newLen),
      buf_(newBuf) {}

StringDataInstance& StringDataInstance::nullInstance() {
    static StaticStringInstance inst(UNKNOWN, -1);
    return inst;
}

const StringDataInstance& StringDataInstance::NULL_INSTANCE() {
    return nullInstance();
}

bool StringDataInstance::isStringCharType(DataType* dataType) {
    if (dataType == nullptr) return false;
    return dynamic_cast<AbstractStringDataType*>(dataType) != nullptr;
}

std::string StringDataInstance::getCharsetNameFromDataTypeOrSettings(DataType* dataType,
                                                                      Settings* settings) {
    if (dataType == nullptr) {
        return DEFAULT_CHARSET_NAME;
    }
    AbstractStringDataType* asdt = dynamic_cast<AbstractStringDataType*>(dataType);
    if (asdt != nullptr) {
        DataTypeWithCharset* dtwcs = dynamic_cast<DataTypeWithCharset*>(asdt);
        if (dtwcs != nullptr) {
            return dtwcs->getCharsetName(settings);
        }
    }
    DataTypeWithCharset* dtwcs2 = dynamic_cast<DataTypeWithCharset*>(dataType);
    if (dtwcs2 != nullptr) {
        return dtwcs2->getCharsetName(settings);
    }
    return DEFAULT_CHARSET_NAME;
}

std::string StringDataInstance::makeStringLabel(const std::string& prefixStr,
                                                const std::string& str,
                                                const DataTypeDisplayOptions& options) {
    int maxLen = options.getLabelStringLength();
    std::string buffer;
    bool needsUnderscore = false;
    int i = 0;
    int n = static_cast<int>(str.size());
    while (i < n && static_cast<int>(buffer.size()) < maxLen) {
        int codePoint = 0;
        int charLen = 1;
        unsigned char c = static_cast<unsigned char>(str[i]);
        if ((c & 0x80) == 0) {
            codePoint = c;
            charLen = 1;
        } else if ((c & 0xE0) == 0xC0) {
            codePoint = (c & 0x1F) << 6;
            if (i + 1 < n) codePoint |= (static_cast<unsigned char>(str[i+1]) & 0x3F);
            charLen = 2;
        } else if ((c & 0xF0) == 0xE0) {
            codePoint = (c & 0x0F) << 12;
            if (i + 1 < n) codePoint |= (static_cast<unsigned char>(str[i+1]) & 0x3F) << 6;
            if (i + 2 < n) codePoint |= (static_cast<unsigned char>(str[i+2]) & 0x3F);
            charLen = 3;
        } else if ((c & 0xF8) == 0xF0) {
            codePoint = (c & 0x07) << 18;
            if (i + 1 < n) codePoint |= (static_cast<unsigned char>(str[i+1]) & 0x3F) << 12;
            if (i + 2 < n) codePoint |= (static_cast<unsigned char>(str[i+2]) & 0x3F) << 6;
            if (i + 3 < n) codePoint |= (static_cast<unsigned char>(str[i+3]) & 0x3F);
            charLen = 4;
        } else {
            codePoint = c;
            charLen = 1;
        }
        if (isDisplayable(codePoint) && codePoint != ' ') {
            if (needsUnderscore && !buffer.empty()) {
                buffer += '_';
            }
            needsUnderscore = false;
            for (int j = 0; j < charLen && i + j < n; ++j) {
                buffer += str[i + j];
            }
        } else {
            needsUnderscore = true;
        }
        i += charLen;
    }
    return prefixStr + buffer;
}

bool StringDataInstance::isBadCharSize() const {
    return (paddedCharSize_ < 1 || paddedCharSize_ > 8) ||
           !(charSize_ == 1 || charSize_ == 2 || charSize_ == 4) ||
           (paddedCharSize_ < charSize_);
}

int StringDataInstance::getStringLength() const {
    if (isPascalLayout(stringLayout_)) {
        return getPascalLength();
    }
    if (isBadCharSize() || buf_ == nullptr || isAlreadyDeterminedFixedLen()) {
        return length_;
    }
    return getNullTerminatedLength();
}

int StringDataInstance::getNullTerminatedLength() const {
    int localLen = length_;
    bool localNT = isNullTerminatedLayout(stringLayout_);
    if (isProbe() || stringLayout_ == StringLayoutEnum::NULL_TERMINATED_UNBOUNDED) {
        localLen = MAX_STRING_LENGTH;
        localNT = true;
    }
    int internalCharOffset = (buf_ != nullptr && buf_->isBigEndian()) ? paddedCharSize_ - charSize_ : 0;
    std::vector<uint8_t> charBuf(charSize_, 0);
    for (int offset = 0; offset < localLen; offset += paddedCharSize_) {
        if (!readChar(charBuf, offset + internalCharOffset)) {
            break;
        }
        if (localNT && isNullChar(charBuf)) {
            return offset + paddedCharSize_;
        }
    }
    return (stringLayout_ == StringLayoutEnum::NULL_TERMINATED_UNBOUNDED) ? -1 : length_;
}

bool StringDataInstance::isMissingNullTerminator() const {
    if (shouldTrimTrailingNulls(stringLayout_)) {
        std::string str = getStringValue();
        return !str.empty() && str.back() != 0;
    }
    return false;
}

int StringDataInstance::getPascalLength() const {
    if (buf_ == nullptr) return -1;
    try {
        switch (stringLayout_) {
            case StringLayoutEnum::PASCAL_255:
                return SIZEOF_PASCAL255_STR_LEN_FIELD +
                       (buf_->getUnsignedByte(0) * paddedCharSize_);
            case StringLayoutEnum::PASCAL_64k:
                return SIZEOF_PASCAL64k_STR_LEN_FIELD +
                       (buf_->getUnsignedShort(0) * paddedCharSize_);
            default:
                return -1;
        }
    } catch (...) {
        return -1;
    }
}

bool StringDataInstance::readChar(std::vector<uint8_t>& charBuf, int offset) const {
    if (buf_ == nullptr) return false;
    std::vector<uint8_t> dst(charBuf.size());
    int n = buf_->getBytes(dst, offset);
    if (n != static_cast<int>(dst.size())) return false;
    charBuf = std::move(dst);
    return true;
}

bool StringDataInstance::isNullChar(const std::vector<uint8_t>& charBuf) const {
    for (uint8_t b : charBuf) {
        if (b != 0) return false;
    }
    return true;
}

std::string StringDataInstance::trimNulls(const std::string& s) const {
    int lastGoodChar = static_cast<int>(s.size()) - 1;
    while (lastGoodChar >= 0 && s[lastGoodChar] == 0) {
        lastGoodChar--;
    }
    return s.substr(0, lastGoodChar + 1);
}

std::string StringDataInstance::getStringValue() const {
    if (isProbe() || isBadCharSize() || buf_ == nullptr || !buf_->isInitializedMemory()) {
        return std::string();
    }
    std::vector<uint8_t> stringBytes = convertPaddedToUnpadded(getStringBytes());
    if (stringBytes.empty() && length_ > 0) {
        return UNKNOWN_DOT_DOT_DOT;
    }
    std::string adjustedCharsetName = charsetName_;
    if (CharsetInfoManager::isBOMCharset(charsetName_)) {
        Endian endian = endianSetting_;
        if (stringBytes.size() >= static_cast<size_t>(charSize_)) {
            if (stringBytes.size() >= 2 && stringBytes[0] == 0xFF && stringBytes[1] == 0xFE) {
                endian = Endian::LITTLE;
            } else if (stringBytes.size() >= 2 && stringBytes[0] == 0xFE && stringBytes[1] == 0xFF) {
                endian = Endian::BIG;
            }
        }
        if (endian == Endian::BIG) adjustedCharsetName += "BE";
        else adjustedCharsetName += "LE";
    }
    try {
        std::string result(reinterpret_cast<const char*>(stringBytes.data()), stringBytes.size());
        (void)adjustedCharsetName;
        return result;
    } catch (...) {
        return UNKNOWN_DOT_DOT_DOT;
    }
}

std::string StringDataInstance::getStringRepresentation() const {
    std::string str = getStringValue();
    if (str.empty()) return UNKNOWN;
    return str;
}

std::string StringDataInstance::getStringRepresentation(bool originalOrTranslated) const {
    (void)originalOrTranslated;
    return getStringRepresentation();
}

std::string StringDataInstance::getCharRepresentation() const {
    if (length_ < charSize_) {
        return UNKNOWN_DOT_DOT_DOT;
    }
    return getStringValue();
}

std::string StringDataInstance::getLabel(const std::string& prefixStr,
                                          const std::string& abbrevPrefixStr,
                                          const std::string& defaultStr,
                                          const DataTypeDisplayOptions& options) const {
    (void)abbrevPrefixStr;
    if (isProbe() || isBadCharSize()) {
        return defaultStr;
    }
    if (options.useAbbreviatedForm()) {
        return prefixStr;
    }
    std::string str = getStringValue();
    if (str.empty()) {
        return prefixStr;
    }
    return makeStringLabel(prefixStr, str, options);
}

std::string StringDataInstance::getOffcutLabelString(const std::string& prefixStr,
                                                       const std::string& abbrevPrefixStr,
                                                       const std::string& defaultStr,
                                                       const DataTypeDisplayOptions& options,
                                                       int byteOffset) const {
    if (isBadCharSize() || isProbe()) {
        return defaultStr;
    }
    StringDataInstance sub = getByteOffcut(byteOffset);
    return sub.getLabel(prefixStr, abbrevPrefixStr, defaultStr, options);
}

StringDataInstance StringDataInstance::getByteOffcut(int byteOffset) const {
    if (isBadCharSize() || isProbe() || !isValidOffcutOffset(byteOffset)) {
        return nullInstance();
    }
    if (byteOffset == 0) {
        return *this;
    }
    int newLength = std::max(0, length_ - byteOffset);
    MemBuffer* newBuf = buf_;
    return StringDataInstance(*this, getOffcutLayout(), newBuf, newLength, charsetName_);
}

StringDataInstance StringDataInstance::getCharOffcut(int offsetChars) const {
    return getByteOffcut(getCharOffset(offsetChars));
}

bool StringDataInstance::isValidOffcutOffset(int offcutBytes) const {
    int minValid = 0;
    if (stringLayout_ == StringLayoutEnum::PASCAL_255) {
        minValid = SIZEOF_PASCAL255_STR_LEN_FIELD;
    } else if (stringLayout_ == StringLayoutEnum::PASCAL_64k) {
        minValid = SIZEOF_PASCAL64k_STR_LEN_FIELD;
    }
    return offcutBytes >= minValid && offcutBytes < length_;
}

int StringDataInstance::getCharOffset(int charCount) const {
    int charBytes = charCount * charSize_;
    if (stringLayout_ == StringLayoutEnum::PASCAL_255) {
        return std::max(0, SIZEOF_PASCAL255_STR_LEN_FIELD + charBytes);
    }
    if (stringLayout_ == StringLayoutEnum::PASCAL_64k) {
        return std::max(0, SIZEOF_PASCAL64k_STR_LEN_FIELD + charBytes);
    }
    return charBytes;
}

StringLayoutEnum StringDataInstance::getOffcutLayout() const {
    if (isPascalLayout(stringLayout_)) {
        return StringLayoutEnum::FIXED_LEN;
    }
    return stringLayout_;
}

std::vector<uint8_t> StringDataInstance::getStringBytes() const {
    if (isPascalLayout(stringLayout_)) {
        return getPascalCharBytes();
    }
    return getNormalStringCharBytes();
}

std::vector<uint8_t> StringDataInstance::getNormalStringCharBytes() const {
    int strLength = getStringLength();
    return getBytesFromMemBuff(buf_, strLength >= 0 ? strLength : length_);
}

std::vector<uint8_t> StringDataInstance::getPascalCharBytes() const {
    if (buf_ == nullptr) return {};
    try {
        int len = 0;
        int offset = 0;
        switch (stringLayout_) {
            case StringLayoutEnum::PASCAL_255:
                len = buf_->getUnsignedByte(0) * paddedCharSize_;
                offset = SIZEOF_PASCAL255_STR_LEN_FIELD;
                break;
            case StringLayoutEnum::PASCAL_64k:
                len = buf_->getUnsignedShort(0) * paddedCharSize_;
                offset = SIZEOF_PASCAL64k_STR_LEN_FIELD;
                break;
            default:
                return {};
        }
        (void)offset;
        std::vector<uint8_t> bytes(len, 0);
        int n = buf_->getBytes(bytes, offset);
        if (n != len) return {};
        return bytes;
    } catch (...) {
        return {};
    }
}

std::vector<uint8_t> StringDataInstance::getBytesFromMemBuff(MemBuffer* memBuffer,
                                                              int copyLen) const {
    if (memBuffer == nullptr) return {};
    if (paddedCharSize_ > 0) {
        copyLen = (copyLen / paddedCharSize_) * paddedCharSize_;
    }
    if (copyLen <= 0) return {};
    std::vector<uint8_t> bytes(copyLen, 0);
    int n = memBuffer->getBytes(bytes, 0);
    if (n != copyLen) return {};
    return bytes;
}

std::vector<uint8_t> StringDataInstance::convertPaddedToUnpadded(
    const std::vector<uint8_t>& paddedBytes) const {
    if (paddedCharSize_ == charSize_ || paddedBytes.empty()) {
        return paddedBytes;
    }
    std::vector<uint8_t> result;
    size_t srcOffset = (buf_ != nullptr && buf_->isBigEndian()) ? paddedCharSize_ - charSize_ : 0;
    while (srcOffset + charSize_ <= paddedBytes.size()) {
        for (int i = 0; i < charSize_; ++i) {
            result.push_back(paddedBytes[srcOffset + i]);
        }
        srcOffset += paddedCharSize_;
    }
    return result;
}

std::vector<uint8_t> StringDataInstance::convertUnpaddedToPadded(
    const std::vector<uint8_t>& unpaddedBytes) const {
    if (paddedCharSize_ == charSize_ || unpaddedBytes.empty()) {
        return unpaddedBytes;
    }
    std::vector<uint8_t> result;
    size_t destOffset = (buf_ != nullptr && buf_->isBigEndian()) ? paddedCharSize_ - charSize_ : 0;
    size_t idx = 0;
    while (idx < unpaddedBytes.size()) {
        while (result.size() < destOffset) result.push_back(0);
        for (int i = 0; i < charSize_ && idx < unpaddedBytes.size(); ++i, ++idx) {
            result.push_back(unpaddedBytes[idx]);
        }
        destOffset = result.size();
    }
    return result;
}

Endian StringDataInstance::getMemoryEndianness() const {
    return (buf_ != nullptr && buf_->isBigEndian()) ? Endian::BIG : Endian::LITTLE;
}

std::string StringDataInstance::getAdjustedCharsetName() const {
    if (CharsetInfoManager::isBOMCharset(charsetName_)) {
        Endian endian = endianSetting_;
        if (endian == Endian::BIG) return charsetName_ + "BE";
        if (endian == Endian::LITTLE) return charsetName_ + "LE";
    }
    return charsetName_;
}

std::vector<uint8_t> StringDataInstance::encodeReplacementFromStringValue(
    const std::string& value) const {
    return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> StringDataInstance::encodeReplacementFromCharValue(
    const std::vector<uint16_t>& value) const {
    std::vector<uint8_t> result;
    for (uint16_t c : value) {
        if (charSize_ >= 1) result.push_back(static_cast<uint8_t>(c & 0xFF));
        if (charSize_ >= 2) result.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    return result;
}

std::vector<uint8_t> StringDataInstance::encodeReplacementFromStringRepresentation(
    const std::string& repr) const {
    return std::vector<uint8_t>(repr.begin(), repr.end());
}

std::vector<uint8_t> StringDataInstance::encodeReplacementFromCharRepresentation(
    const std::string& repr) const {
    return std::vector<uint8_t>(repr.begin(), repr.end());
}

//--------------------------------------------------------------------------------------
// StaticStringInstance
//--------------------------------------------------------------------------------------

StaticStringInstance::StaticStringInstance(const std::string& fakeStr, int fakeLen) {
    fakeStr_ = fakeStr;
    fakeLen_ = fakeLen;
    charsetName_ = "?";
    stringLayout_ = StringLayoutEnum::FIXED_LEN;
    length_ = fakeLen;
}

} // namespace ghidra
