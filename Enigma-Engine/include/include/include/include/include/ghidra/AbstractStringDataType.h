/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractStringDataType.h
/// \brief Common base class for all Ghidra string DataTypes.
#pragma once

#include "BuiltIn.h"
#include "StringLayoutEnum.h"

namespace ghidra {

class MemBuffer;
class Settings;
class StringDataInstance;

/**
 * Common base class for all Ghidra string DataTypes.
 * Translated from: ghidra.program.model.data.AbstractStringDataType
 */
class AbstractStringDataType : public BuiltIn {
protected:
    std::string mnemonic_;
    std::string defaultLabel_;
    std::string defaultLabelPrefix_;
    std::string defaultAbbrevLabelPrefix_;
    std::string description_;
    DataType* replacementDataType_;
    StringLayoutEnum stringLayoutEnum_;

    AbstractStringDataType(const std::string& name, const std::string& mnemonic,
                           const std::string& defaultLabel, const std::string& defaultLabelPrefix,
                           const std::string& defaultAbbrevLabelPrefix, const std::string& description,
                           DataType* replacementDataType, DataTypeManager* dtm);

public:
    virtual ~AbstractStringDataType();

    std::string getMnemonic(Settings* settings) const override;

    std::string getDefaultLabelPrefix() const override;

    std::string getDescription() const override;

    int getLength() const override;

    const std::type_info& getValueClass(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;

    DataType* getReplacementBaseType() const override;

    /// Returns the StringLayoutEnum that this string type uses.  Default is FIXED_LEN.
    virtual StringLayoutEnum getStringLayout() const { return stringLayoutEnum_; }

    /// Set the StringLayoutEnum for this string type.  Called by concrete subclasses
    /// in their constructor to declare the layout they implement.
    void setStringLayout(StringLayoutEnum layout) { stringLayoutEnum_ = layout; }

    /// Construct a StringDataInstance for the given memory buffer.
    virtual StringDataInstance getStringDataInstance(MemBuffer* buf, Settings* settings,
                                                      int length) const;

    static const std::string DEFAULT_LABEL;
    static const std::string DEFAULT_ABBREV_PREFIX;
    static const std::string DEFAULT_LABEL_PREFIX;
    static const std::string DEFAULT_UNICODE;
    static const std::string DEFAULT_UNICODE_LABEL;
    static const std::string DEFAULT_UNICODE_LABEL_PREFIX;
    static const std::string DEFAULT_UNICODE_ABBREV_PREFIX;
};

} // namespace ghidra
