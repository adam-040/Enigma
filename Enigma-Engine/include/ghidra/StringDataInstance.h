/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StringDataInstance.h
/// \brief Represents an instance of a string in a MemBuffer.
/// Translated from: ghidra.program.model.data.StringDataInstance
#pragma once

#include "Endian.h"
#include "RenderUnicodeSettingsDefinition.h"
#include "StringLayoutEnum.h"
#include "TranslationSettingsDefinition.h"
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class DataType;
class DataTypeManager;
class MemBuffer;
class Settings;
class Address;
class DataTypeDisplayOptions;

/**
 * Represents an instance of a string in a MemBuffer.  Handles the details of
 * detecting a terminated string's length, converting the bytes in the
 * membuffer into a native String, and converting the raw String into a
 * formatted human-readable version, according to the various
 * SettingsDefinitions attached to the string data location.
 *
 * The property-map methods (getTranslatedValue reading from
 * StringPropertyMap, etc.) are not ported: PropertyMapManager and
 * StringPropertyMap are not yet ported.
 *
 * Translated from: ghidra.program.model.data.StringDataInstance
 */
class StringDataInstance {
public:
    static const int MAX_STRING_LENGTH = 16 * 1024;
    static const std::string DEFAULT_CHARSET_NAME;
    static const std::string UNKNOWN;
    static const std::string UNKNOWN_DOT_DOT_DOT;

    static const int SIZEOF_PASCAL255_STR_LEN_FIELD = 1;
    static const int SIZEOF_PASCAL64k_STR_LEN_FIELD = 2;

    StringDataInstance(DataType* dataType, Settings* settings, MemBuffer* buf, int length);
    StringDataInstance(DataType* dataType, Settings* settings, MemBuffer* buf, int length,
                       bool isArrayElement);

    virtual ~StringDataInstance() = default;

    static bool isStringCharType(DataType* dataType);
    static std::string getCharsetNameFromDataTypeOrSettings(DataType* dataType, Settings* settings);
    static std::string makeStringLabel(const std::string& prefixStr, const std::string& str,
                                       const DataTypeDisplayOptions& options);

    const std::string& getCharsetName() const { return charsetName_; }
    int getCharSize() const { return charSize_; }
    int getPaddedCharSize() const { return paddedCharSize_; }
    StringLayoutEnum getLayout() const { return stringLayout_; }
    int getDataLength() const { return length_; }

    virtual int getStringLength() const;
    virtual bool isMissingNullTerminator() const;
    virtual std::string getStringValue() const;
    virtual std::string getStringRepresentation() const;
    virtual std::string getStringRepresentation(bool originalOrTranslated) const;
    virtual std::string getCharRepresentation() const;
    virtual std::string getLabel(const std::string& prefixStr, const std::string& abbrevPrefixStr,
                                 const std::string& defaultStr,
                                 const DataTypeDisplayOptions& options) const;
    virtual std::string getOffcutLabelString(const std::string& prefixStr,
                                              const std::string& abbrevPrefixStr,
                                              const std::string& defaultStr,
                                              const DataTypeDisplayOptions& options,
                                              int byteOffset) const;

    StringDataInstance getByteOffcut(int byteOffset) const;
    StringDataInstance getCharOffcut(int offsetChars) const;

    std::vector<uint8_t> encodeReplacementFromStringValue(const std::string& value) const;
    std::vector<uint8_t> encodeReplacementFromCharValue(const std::vector<uint16_t>& value) const;
    std::vector<uint8_t> encodeReplacementFromCharRepresentation(const std::string& repr) const;
    std::vector<uint8_t> encodeReplacementFromStringRepresentation(const std::string& repr) const;

    static const StringDataInstance& NULL_INSTANCE();

protected:
    StringDataInstance()
        : charsetName_("??"), charSize_(0), paddedCharSize_(0),
          stringLayout_(StringLayoutEnum::FIXED_LEN), translatedValue_(),
          endianSetting_(Endian::LITTLE), showTranslation_(false),
          renderSetting_(RenderUnicodeEnum::ALL), length_(0), buf_(nullptr) {}

    StringDataInstance(const StringDataInstance& copyFrom, StringLayoutEnum newLayout,
                       MemBuffer* newBuf, int newLen, const std::string& newCharsetName);

    std::string charsetName_;
    int charSize_;
    int paddedCharSize_;
    StringLayoutEnum stringLayout_;
    std::string translatedValue_;
    Endian endianSetting_;
    bool showTranslation_;
    RenderUnicodeEnum renderSetting_;
    int length_;
    MemBuffer* buf_;

    static StringDataInstance& nullInstance();

    bool isProbe() const { return length_ == -1; }
    bool isBadCharSize() const;
    bool isAlreadyDeterminedFixedLen() const { return length_ >= 0 && isFixedLenLayout(stringLayout_); }
    int getPascalLength() const;
    int getNullTerminatedLength() const;
    int getCharOffset(int charCount) const;
    StringLayoutEnum getOffcutLayout() const;
    std::vector<uint8_t> getStringBytes() const;
    std::vector<uint8_t> getNormalStringCharBytes() const;
    std::vector<uint8_t> getPascalCharBytes() const;
    std::vector<uint8_t> convertPaddedToUnpadded(const std::vector<uint8_t>& paddedBytes) const;
    std::vector<uint8_t> convertUnpaddedToPadded(const std::vector<uint8_t>& unpaddedBytes) const;
    Endian getMemoryEndianness() const;
    std::string getAdjustedCharsetName() const;
    std::string trimNulls(const std::string& s) const;
    std::vector<uint8_t> getBytesFromMemBuff(MemBuffer* memBuffer, int copyLen) const;
    bool readChar(std::vector<uint8_t>& charBuf, int offset) const;
    bool isNullChar(const std::vector<uint8_t>& charBuf) const;
    bool isValidOffcutOffset(int offcutBytes) const;
};

/**
 * A StringDataInstance that represents a non-existent string.  Methods on
 * this instance generally return defaults (empty string, 0, false).
 *
 * Translated from: ghidra.program.model.data.StringDataInstance.StaticStringInstance
 */
class StaticStringInstance : public StringDataInstance {
public:
    StaticStringInstance(const std::string& fakeStr, int fakeLen);

    int getStringLength() const override { return fakeLen_; }
    std::string getStringValue() const override { return fakeStr_; }
    std::string getStringRepresentation() const override { return fakeStr_; }
    std::string getLabel(const std::string& prefixStr, const std::string& abbrevPrefixStr,
                         const std::string& defaultStr,
                         const DataTypeDisplayOptions& options) const override {
        (void)prefixStr; (void)abbrevPrefixStr; (void)options; return defaultStr;
    }
    std::string getOffcutLabelString(const std::string& prefixStr,
                                      const std::string& abbrevPrefixStr,
                                      const std::string& defaultStr,
                                      const DataTypeDisplayOptions& options,
                                      int offcutOffset) const override {
        (void)prefixStr; (void)abbrevPrefixStr; (void)options; (void)offcutOffset; return defaultStr;
    }

private:
    std::string fakeStr_;
    int fakeLen_;
};

} // namespace ghidra
