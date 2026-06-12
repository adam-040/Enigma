/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractStringDataType.cpp
/// \brief Common base class for all Ghidra string DataTypes implementation
#include "ghidra/AbstractStringDataType.h"
#include "ghidra/StringDataInstance.h"

namespace ghidra {

AbstractStringDataType::AbstractStringDataType(const std::string& name, const std::string& mnemonic,
                                               const std::string& defaultLabel, const std::string& defaultLabelPrefix,
                                               const std::string& defaultAbbrevLabelPrefix, const std::string& description,
                                               DataType* replacementDataType, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm),
      mnemonic_(mnemonic),
      defaultLabel_(defaultLabel),
      defaultLabelPrefix_(defaultLabelPrefix),
      defaultAbbrevLabelPrefix_(defaultAbbrevLabelPrefix),
      description_(description),
      replacementDataType_(replacementDataType),
      stringLayoutEnum_(StringLayoutEnum::FIXED_LEN) {}

AbstractStringDataType::~AbstractStringDataType() = default;

std::string AbstractStringDataType::getMnemonic(Settings* settings) const {
    return mnemonic_;
}

std::string AbstractStringDataType::getDefaultLabelPrefix() const {
    return defaultLabelPrefix_;
}

std::string AbstractStringDataType::getDescription() const {
    return description_;
}

int AbstractStringDataType::getLength() const {
    return -1;
}

const std::type_info& AbstractStringDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

std::string AbstractStringDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

DataType* AbstractStringDataType::getReplacementBaseType() const {
    return replacementDataType_;
}

StringDataInstance AbstractStringDataType::getStringDataInstance(MemBuffer* buf,
                                                                 Settings* settings,
                                                                 int length) const {
    return StringDataInstance(const_cast<AbstractStringDataType*>(this), settings, buf, length);
}

const std::string AbstractStringDataType::DEFAULT_LABEL = "STRING";
const std::string AbstractStringDataType::DEFAULT_ABBREV_PREFIX = "s";
const std::string AbstractStringDataType::DEFAULT_LABEL_PREFIX = "STR";
const std::string AbstractStringDataType::DEFAULT_UNICODE = "UNICODE";
const std::string AbstractStringDataType::DEFAULT_UNICODE_LABEL = "UNICODE";
const std::string AbstractStringDataType::DEFAULT_UNICODE_LABEL_PREFIX = "UNI";
const std::string AbstractStringDataType::DEFAULT_UNICODE_ABBREV_PREFIX = "u";

} // namespace ghidra
