/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AbstractLeb128DataType.h>
#include <ghidra/LEB128.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/Scalar.h>
#include <ghidra/Settings.h>
#include <ghidra/CategoryPath.h>
#include <typeinfo>

namespace ghidra {

AbstractLeb128DataType::AbstractLeb128DataType(const std::string& name, bool isSigned, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm), Dynamic(), isSigned_(isSigned) {}

std::string AbstractLeb128DataType::getMnemonic(Settings* settings) const {
    return getName();
}

const std::type_info& AbstractLeb128DataType::getValueClass(Settings* settings) const {
    return typeid(Scalar);
}

std::string AbstractLeb128DataType::getDescription() const {
    return isSigned_ ? "Signed LEB128-Encoded Number" : "Unsigned LEB128-Encoded Number";
}

int AbstractLeb128DataType::getLength() const {
    return -1;
}

bool AbstractLeb128DataType::canSpecifyLength() {
    return true;
}

DataType* AbstractLeb128DataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string AbstractLeb128DataType::getDefaultLabelPrefix() const {
    return getName();
}

std::string AbstractLeb128DataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    if (!buf) return "??";
    int maxLen = LEB128::MAX_SUPPORTED_LENGTH;
    int maxRead = (length > 0 && length < maxLen) ? length : maxLen;
    uint8_t tmp[LEB128::MAX_SUPPORTED_LENGTH];
    int read = buf->getBytes(tmp, maxRead, 0);
    if (read <= 0) return "??";
    int encLen = LEB128::getLength(tmp, 0, static_cast<size_t>(read));
    if (encLen <= 0 || encLen > read) return "??";
    if (isSigned_) {
        int64_t val = LEB128::signedDecode(tmp, 0, static_cast<size_t>(encLen));
        return Scalar(encLen * 8, val, true).toString();
    } else {
        uint64_t val = LEB128::unsignedDecode(tmp, 0, static_cast<size_t>(encLen));
        return Scalar(encLen * 8, static_cast<int64_t>(val), false).toString();
    }
}

int AbstractLeb128DataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    int maxLen = LEB128::MAX_SUPPORTED_LENGTH;
    int readLen = (maxLength > 0 && maxLength < maxLen) ? maxLength : maxLen;
    uint8_t tmp[LEB128::MAX_SUPPORTED_LENGTH];
    int read = buf->getBytes(tmp, readLen, 0);
    if (read <= 0) return -1;
    int len = LEB128::getLength(tmp, 0, static_cast<size_t>(read));
    return (len > 0) ? len : -1;
}

std::string AbstractLeb128DataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return getDecompilerDisplayName();
}

void AbstractLeb128DataType::setDefaultSettings(Settings* settings) {
    BuiltIn::setDefaultSettings(settings);
}

} // namespace ghidra
