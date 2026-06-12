/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\FunctionDefinitionDataType.h>

namespace ghidra {

void FunctionDefinitionDataType::deleteOwnedParameter(ParameterDefinition* param) {
    if (!param) return;
    delete param;
}

void FunctionDefinitionDataType::clearArguments() {
    for (auto* param : params_) {
        deleteOwnedParameter(param);
    }
    params_.clear();
}

void FunctionDefinitionDataType::assignReturnType(DataType* type, bool ownsReturnType) {
    if (ownsReturnType_ && returnType_ != type) {
        delete returnType_;
    }
    returnType_ = type;
    ownsReturnType_ = ownsReturnType;
}

void FunctionDefinitionDataType::copySignature(const FunctionSignature* sig) {
    comment_ = sig->getComment();
    DataType* rtnType = sig->getReturnType();
    DataType* clonedReturnType = rtnType ? rtnType->clone(getDataTypeManager()) : nullptr;
    assignReturnType(clonedReturnType, clonedReturnType && clonedReturnType != rtnType);
    
    auto args = sig->getArguments();
    std::vector<ParameterDefinition*> newArgs;
    for (auto arg : args) {
        DataType* clonedDataType = arg->getDataType()->clone(getDataTypeManager());
        newArgs.push_back(new ParameterDefinitionImpl(
            arg->getName(),
            clonedDataType,
            arg->getComment(),
            arg->getOrdinal(),
            clonedDataType != arg->getDataType()));
    }
    setArguments(newArgs);
    
    hasVarArgs_ = sig->hasVarArgs();
    hasNoReturn_ = sig->hasNoReturn();
    callingConventionName_ = sig->getCallingConventionName();
}

FunctionDefinitionDataType::FunctionDefinitionDataType(const std::string& name, DataTypeManager* dtm)
    : FunctionDefinitionDataType(CategoryPath::ROOT(), name, nullptr, dtm) {}

FunctionDefinitionDataType::FunctionDefinitionDataType(const CategoryPath& path, const std::string& name, const FunctionSignature* sig, DataTypeManager* dtm)
    : GenericDataType(path, name, dtm),
      returnType_(nullptr),
      hasVarArgs_(false),
      hasNoReturn_(false),
      ownsReturnType_(false),
      callingConventionName_(GenericCallingConvention::unknown) {
    if (sig) {
        copySignature(sig);
    }
}

FunctionDefinitionDataType::~FunctionDefinitionDataType() {
    clearArguments();
    if (ownsReturnType_) {
        delete returnType_;
    }
}

void FunctionDefinitionDataType::setArguments(const std::vector<ParameterDefinition*>& args) {
    clearArguments();
    for (size_t i = 0; i < args.size(); i++) {
        DataType* clonedDataType = args[i]->getDataType()->clone(getDataTypeManager());
        params_.push_back(new ParameterDefinitionImpl(args[i]->getName(), 
                          clonedDataType,
                          args[i]->getComment(), i,
                          clonedDataType != args[i]->getDataType()));
    }
}

void FunctionDefinitionDataType::setReturnType(DataType* type) {
    assignReturnType(type, false);
}

void FunctionDefinitionDataType::setComment(const std::string& comment) {
    comment_ = comment;
}

void FunctionDefinitionDataType::setVarArgs(bool hasVarArgs) {
    hasVarArgs_ = hasVarArgs;
}

void FunctionDefinitionDataType::setNoReturn(bool hasNoReturn) {
    hasNoReturn_ = hasNoReturn;
}

void FunctionDefinitionDataType::setCallingConvention(const std::string& conventionName) {
    callingConventionName_ = conventionName;
}

DataType* FunctionDefinitionDataType::clone(DataTypeManager* dtm) const {
    if (getDataTypeManager() == dtm) {
        return const_cast<FunctionDefinitionDataType*>(this);
    }
    return new FunctionDefinitionDataType(getCategoryPath(), getName(), this, dtm);
}

DataType* FunctionDefinitionDataType::copy(DataTypeManager* dtm) const {
    return clone(dtm);
}

std::string FunctionDefinitionDataType::getMnemonic(Settings* settings) const {
    return getPrototypeString();
}

int FunctionDefinitionDataType::getLength() const {
    return -1;
}

std::string FunctionDefinitionDataType::getDescription() const {
    return "Function:     " + getMnemonic(nullptr);
}

std::string FunctionDefinitionDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return getPrototypeString();
}

const std::type_info& FunctionDefinitionDataType::getValueClass(Settings* settings) const {
    return typeid(void);
}

std::string FunctionDefinitionDataType::getPrototypeString() const {
    return getPrototypeString(false);
}

std::string FunctionDefinitionDataType::getPrototypeString(bool includeCallingConvention) const {
    std::string buf;
    if (includeCallingConvention && hasNoReturn_) {
        buf += FunctionSignature::NORETURN_DISPLAY_STRING + " ";
    }
    buf += (returnType_ ? returnType_->getDisplayName() : "void") + " ";
    if (includeCallingConvention && callingConventionName_ != "unknown") {
        buf += callingConventionName_ + " ";
    }
    buf += name_ + "(";
    for (size_t i = 0; i < params_.size(); i++) {
        buf += params_[i]->getDataType()->getDisplayName() + " " + params_[i]->getName();
        if (i < params_.size() - 1 || hasVarArgs_) {
            buf += ", ";
        }
    }
    if (hasVarArgs_) {
        buf += FunctionSignature::VAR_ARGS_DISPLAY_STRING;
    } else if (params_.empty()) {
        buf += FunctionSignature::VOID_PARAM_DISPLAY_STRING;
    }
    buf += ")";
    return buf;
}

std::vector<ParameterDefinition*> FunctionDefinitionDataType::getArguments() const {
    return params_;
}

DataType* FunctionDefinitionDataType::getReturnType() const {
    return returnType_;
}

std::string FunctionDefinitionDataType::getComment() const {
    return comment_;
}

bool FunctionDefinitionDataType::hasVarArgs() const {
    return hasVarArgs_;
}

bool FunctionDefinitionDataType::hasNoReturn() const {
    return hasNoReturn_;
}

std::string FunctionDefinitionDataType::getCallingConventionName() const {
    return callingConventionName_;
}

bool FunctionDefinitionDataType::isEquivalent(const DataType* dt) const {
    if (dt == this) return true;
    const FunctionDefinition* sig = dynamic_cast<const FunctionDefinition*>(dt);
    if (!sig) return false;
    return isEquivalentSignature(sig);
}

bool FunctionDefinitionDataType::isEquivalentSignature(const FunctionSignature* signature) const {
    if (signature == this) return true;
    if (signature->getName() == name_ && 
        signature->getComment() == comment_ &&
        hasVarArgs_ == signature->hasVarArgs() &&
        hasNoReturn_ == signature->hasNoReturn() &&
        callingConventionName_ == signature->getCallingConventionName()) {
        
        DataType* otherRt = signature->getReturnType();
        if ((returnType_ == nullptr && otherRt != nullptr) || 
            (returnType_ != nullptr && !returnType_->isEquivalent(otherRt))) {
            return false;
        }
        
        auto otherArgs = signature->getArguments();
        if (otherArgs.size() != params_.size()) return false;
        
        for (size_t i = 0; i < params_.size(); i++) {
            if (!params_[i]->isEquivalent(otherArgs[i])) {
                return false;
            }
        }
        return true;
    }
    return false;
}

std::string FunctionDefinitionDataType::getName() const {
    return name_;
}

} // namespace ghidra
