/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParameterDefinitionImpl.cpp
/// \brief Basic implementation of ParameterDefinition
/// Translated from: ghidra.program.model.data.ParameterDefinitionImpl

#include <ghidra/ParameterDefinitionImpl.h>
#include <sstream>

namespace ghidra {

ParameterDefinitionImpl::ParameterDefinitionImpl(const std::string& name, DataType* dataType,
    const std::string& comment, int ordinal, bool ownsDataType)
    : ordinal_(ordinal), name_(name), dataType_(dataType), ownsDataType_(ownsDataType), comment_(comment) {}

ParameterDefinitionImpl::~ParameterDefinitionImpl() {
    if (ownsDataType_ && dataType_) {
        delete dataType_;
    }
}

void ParameterDefinitionImpl::setDataType(DataType* type) {
    if (ownsDataType_ && dataType_) {
        delete dataType_;
    }
    dataType_ = type;
    ownsDataType_ = false;
}

void ParameterDefinitionImpl::setComment(const std::string& comment) {
    comment_ = comment;
}

bool ParameterDefinitionImpl::isEquivalent(const ParameterDefinition* parm) const {
    if (!parm) return false;
    if (ordinal_ != parm->getOrdinal()) return false;
    if (name_ != parm->getName()) return false;
    if (comment_ != parm->getComment()) return false;
    if (!dataType_ && !parm->getDataType()) return true;
    if (!dataType_ || !parm->getDataType()) return false;
    return dataType_->isEquivalent(parm->getDataType());
}

std::string ParameterDefinitionImpl::toString() const {
    std::ostringstream ss;
    ss << "ParameterDefinitionImpl[" << name_;
    if (dataType_) {
        ss << ", type=" << dataType_->getName();
        ss << ", length=" << dataType_->getLength();
    }
    if (!comment_.empty()) {
        ss << ", comment=" << comment_;
    }
    ss << "]";
    return ss.str();
}

} // namespace ghidra
