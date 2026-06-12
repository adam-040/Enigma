/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionSignatureImpl.cpp
/// \brief Concrete implementation of FunctionSignature
#include "ghidra/FunctionSignatureImpl.h"
#include "ghidra/ParameterDefinitionImpl.h"
#include <sstream>

namespace ghidra {

FunctionSignatureImpl::FunctionSignatureImpl()
    : returnType_(nullptr), hasVarArgs_(false), hasNoReturn_(false) {}

FunctionSignatureImpl::FunctionSignatureImpl(const std::string& name)
    : name_(name), returnType_(nullptr), hasVarArgs_(false), hasNoReturn_(false) {}

std::string FunctionSignatureImpl::getName() const {
    return name_;
}

void FunctionSignatureImpl::setName(const std::string& name) {
    name_ = name;
}

std::vector<ParameterDefinition*> FunctionSignatureImpl::getArguments() const {
    std::vector<ParameterDefinition*> result;
    for (const auto& arg : arguments_) {
        result.push_back(arg.get());
    }
    return result;
}

void FunctionSignatureImpl::setArguments(const std::vector<ParameterDefinition*>& args) {
    arguments_.clear();
    for (auto* arg : args) {
        arguments_.push_back(std::unique_ptr<ParameterDefinition>(arg));
    }
}

void FunctionSignatureImpl::addArgument(ParameterDefinition* arg) {
    if (arg) {
        arguments_.push_back(std::unique_ptr<ParameterDefinition>(arg));
    }
}

void FunctionSignatureImpl::clearArguments() {
    arguments_.clear();
}

DataType* FunctionSignatureImpl::getReturnType() const {
    return returnType_;
}

void FunctionSignatureImpl::setReturnType(DataType* type) {
    returnType_ = type;
}

std::string FunctionSignatureImpl::getComment() const {
    return comment_;
}

void FunctionSignatureImpl::setComment(const std::string& comment) {
    comment_ = comment;
}

bool FunctionSignatureImpl::hasVarArgs() const {
    return hasVarArgs_;
}

void FunctionSignatureImpl::setHasVarArgs(bool varArgs) {
    hasVarArgs_ = varArgs;
}

bool FunctionSignatureImpl::hasNoReturn() const {
    return hasNoReturn_;
}

void FunctionSignatureImpl::setHasNoReturn(bool noReturn) {
    hasNoReturn_ = noReturn;
}

std::string FunctionSignatureImpl::getCallingConventionName() const {
    return callingConventionName_;
}

void FunctionSignatureImpl::setCallingConventionName(const std::string& name) {
    callingConventionName_ = name;
}

std::string FunctionSignatureImpl::getPrototypeString() const {
    return getPrototypeString(false);
}

std::string FunctionSignatureImpl::getPrototypeString(bool includeCallingConvention) const {
    std::stringstream ss;

    if (hasNoReturn_) {
        ss << NORETURN_DISPLAY_STRING << " ";
    } else if (returnType_) {
        ss << returnType_->getName() << " ";
    } else {
        ss << "void ";
    }

    ss << name_ << "(";

    if (arguments_.empty() && !hasVarArgs_) {
        ss << VOID_PARAM_DISPLAY_STRING;
    } else {
        for (size_t i = 0; i < arguments_.size(); ++i) {
            if (i > 0) ss << ", ";
            auto* arg = arguments_[i].get();
            if (arg) {
                if (arg->getDataType()) {
                    ss << arg->getDataType()->getName();
                }
                if (!arg->getName().empty()) {
                    ss << " " << arg->getName();
                }
            }
        }
        if (hasVarArgs_) {
            if (!arguments_.empty()) ss << ", ";
            ss << VAR_ARGS_DISPLAY_STRING;
        }
    }

    ss << ")";

    if (includeCallingConvention && !callingConventionName_.empty()) {
        ss << " __" << callingConventionName_;
    }

    return ss.str();
}

bool FunctionSignatureImpl::isEquivalentSignature(const FunctionSignature* signature) const {
    if (!signature) return false;
    if (this == signature) return true;

    if (name_ != signature->getName()) return false;
    if (hasVarArgs_ != signature->hasVarArgs()) return false;
    if (hasNoReturn_ != signature->hasNoReturn()) return false;

    auto args = getArguments();
    auto otherArgs = signature->getArguments();
    if (args.size() != otherArgs.size()) return false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (!args[i]->isEquivalent(otherArgs[i])) return false;
    }

    if (returnType_ && signature->getReturnType()) {
        if (!returnType_->isEquivalent(signature->getReturnType())) return false;
    } else if (returnType_ != signature->getReturnType()) {
        return false;
    }

    return true;
}

FunctionSignatureImpl* FunctionSignatureImpl::clone() const {
    auto* clone = new FunctionSignatureImpl(name_);
    clone->setComment(comment_);
    clone->setCallingConventionName(callingConventionName_);
    clone->setReturnType(returnType_);
    clone->setHasVarArgs(hasVarArgs_);
    clone->setHasNoReturn(hasNoReturn_);

    for (const auto& arg : arguments_) {
        if (arg) {
            clone->addArgument(new ParameterDefinitionImpl(
                arg->getName(), arg->getDataType(), arg->getComment(),
                arg->getOrdinal()));
        }
    }

    return clone;
}

} // namespace ghidra
