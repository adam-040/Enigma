/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Function.cpp
/// \brief Function representation in the program listing
#include <ghidra/Function.h>
#include <ghidra/FunctionSignature.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/DataType.h>
#include <ghidra/Variable.h>
#include <ghidra/StackFrame.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionTagManager.h>
#include <ghidra/FunctionTag.h>
#include <sstream>
#include <algorithm>

namespace ghidra {

Function::Function(const std::string& name, Address entryPoint, Namespace* parent,
                   SourceType source)
    : Symbol(name, entryPoint, parent, source, SymbolType::FUNCTION, -1),
      entryPoint_(entryPoint), program_(nullptr) {
}

Function::~Function() {
    delete stackFrame_;
    for (auto* param : parameters_) {
        delete param;
    }
    for (auto* var : localVariables_) {
        delete var;
    }
}

std::vector<Variable*> Function::getAllVariables() const {
    std::vector<Variable*> result;
    result.reserve(parameters_.size() + localVariables_.size());
    result.insert(result.end(), parameters_.begin(), parameters_.end());
    result.insert(result.end(), localVariables_.begin(), localVariables_.end());
    return result;
}

void Function::removeVariable(Variable* var) {
    if (!var) return;
    auto it = std::find(parameters_.begin(), parameters_.end(), var);
    if (it != parameters_.end()) {
        parameters_.erase(it);
    }
    auto it2 = std::find(localVariables_.begin(), localVariables_.end(), var);
    if (it2 != localVariables_.end()) {
        localVariables_.erase(it2);
    }
}

std::string Function::getSignatureString() const {
    std::ostringstream ss;
    if (returnType_) {
        ss << returnType_->getName() << " ";
    } else {
        ss << "void ";
    }
    ss << getName() << "(";
    for (size_t i = 0; i < parameters_.size(); i++) {
        if (i > 0) ss << ", ";
        if (parameters_[i]->getDataType()) {
            ss << parameters_[i]->getDataType()->getName();
        } else {
            ss << "unknown";
        }
        ss << " " << parameters_[i]->getName();
    }
    ss << ")";
    return ss.str();
}

std::string Function::toString() const {
    std::ostringstream ss;
    ss << "Function: " << getName() << " @ " << entryPoint_.toString();
    ss << " (stack=" << stackFrameSize_ << ")";
    if (isThunk_) ss << " [thunk]";
    if (isExternal_) ss << " [external]";
    if (hasNoReturn_) ss << " [noreturn]";
    return ss.str();
}

bool Function::addTag(const std::string& name) {
    if (!program_) return false;
    auto* tagMgr = program_->getFunctionTagManager();
    if (!tagMgr) return false;
    auto* tag = tagMgr->createFunctionTag(name, "");
    if (!tag) return false;

    // Check if already contains
    auto it = std::find_if(tags_.begin(), tags_.end(),
        [tag](FunctionTag* t) { return t && t->getId() == tag->getId(); });
    if (it == tags_.end()) {
        tags_.push_back(tag);
        return true;
    }
    return false;
}

void Function::removeTag(const std::string& name) {
    tags_.erase(std::remove_if(tags_.begin(), tags_.end(),
        [&name](FunctionTag* t) { return t && t->getName() == name; }), tags_.end());
}

bool Function::setSignature(FunctionSignature* sig, SignatureSource source) {
    if (!signatureSourceOutranks(source, signatureSource_)) return false;
    signature_ = sig;
    signatureSource_ = source;
    return true;
}

bool Function::setCallingConvention(PrototypeModel* model, SignatureSource source) {
    if (!signatureSourceOutranks(source, callingConventionSource_)) return false;
    callingConvention_ = model;
    callingConventionSource_ = source;
    return true;
}

bool Function::setReturnType(DataType* type, SignatureSource source) {
    if (!signatureSourceOutranks(source, returnTypeSource_)) return false;
    returnType_ = type;
    returnTypeSource_ = source;
    return true;
}

bool Function::addParameter(Variable* param, SignatureSource source) {
    if (!signatureSourceOutranks(source, paramSource_)) return false;
    parameters_.push_back(param);
    paramSource_ = source;
    return true;
}

bool Function::setHasNoReturn(bool v, SignatureSource source) {
    if (!signatureSourceOutranks(source, noReturnSource_)) return false;
    hasNoReturn_ = v;
    noReturnSource_ = source;
    return true;
}

} // namespace ghidra
