/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParameterDefinitionImpl.h
/// \brief Basic implementation of ParameterDefinition.
#pragma once

#include "ParameterDefinition.h"

namespace ghidra {

/**
 * Basic implementation of ParameterDefinition.
 * Translated from: ghidra.program.model.data.ParameterDefinitionImpl
 */
class ParameterDefinitionImpl : public ParameterDefinition {
protected:
    int ordinal_;
    std::string name_;
    DataType* dataType_;
    bool ownsDataType_;
    std::string comment_;

public:
    ParameterDefinitionImpl(const std::string& name, DataType* dataType, const std::string& comment, int ordinal = -1,
                            bool ownsDataType = false);

    ~ParameterDefinitionImpl() override;

    int getOrdinal() const override {
        return ordinal_;
    }

    DataType* getDataType() const override {
        return dataType_;
    }

    void setDataType(DataType* type) override;

    std::string getName() const override {
        return name_;
    }

    int getLength() const override {
        return dataType_->getLength();
    }

    void setName(const std::string& name) override {
        name_ = name;
    }

    std::string getComment() const override {
        return comment_;
    }

    void setComment(const std::string& comment) override;

    bool isEquivalent(const ParameterDefinition* parm) const override;

    bool ownsDataType() const {
        return ownsDataType_;
    }

    std::string toString() const;
};

} // namespace ghidra
