/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Function.h
/// \brief Function representation in the program listing
/// Translated from: ghidra.program.model.listing.Function
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Namespace.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/Symbol.h>
#include <ghidra/Variable.h>
#include <string>
#include <vector>

namespace ghidra {

class FunctionSignature;
class ParameterDefinition;
class DataType;
class Instruction;
class FunctionTag;
class StackFrame;


class Function : public Symbol {
public:
    Function() = default;
    Function(const std::string& name, Address entryPoint, Namespace* parent,
             SourceType source);
    virtual ~Function();

    Program* getProgram() const { return program_; }
    void setProgram(Program* prog) { program_ = prog; }

    Address getEntryPoint() const { return entryPoint_; }
    void setEntryPoint(Address addr) { entryPoint_ = addr; }

    const AddressSet& getBody() const { return body_; }
    void setBody(const AddressSet& body) { body_ = body; }

    FunctionSignature* getSignature() const { return signature_; }
    void setSignature(FunctionSignature* sig) { signature_ = sig; }
    bool setSignature(FunctionSignature* sig, SignatureSource source);

    SignatureSource getSignatureSource() const {
        SignatureSource s = SignatureSource::UNKNOWN;
        if (static_cast<uint8_t>(returnTypeSource_) > static_cast<uint8_t>(s)) s = returnTypeSource_;
        if (static_cast<uint8_t>(callingConventionSource_) > static_cast<uint8_t>(s)) s = callingConventionSource_;
        if (static_cast<uint8_t>(paramSource_) > static_cast<uint8_t>(s)) s = paramSource_;
        if (static_cast<uint8_t>(noReturnSource_) > static_cast<uint8_t>(s)) s = noReturnSource_;
        if (static_cast<uint8_t>(signatureSource_) > static_cast<uint8_t>(s)) s = signatureSource_;
        return s;
    }
    void setSignatureSource(SignatureSource s) { signatureSource_ = s; }

    PrototypeModel* getCallingConvention() const { return callingConvention_; }
    void setCallingConvention(PrototypeModel* model) { callingConvention_ = model; }
    bool setCallingConvention(PrototypeModel* model, SignatureSource source);

    DataType* getReturnType() const { return returnType_; }
    void setReturnType(DataType* type) { returnType_ = type; }
    bool setReturnType(DataType* type, SignatureSource source);

    const std::vector<Variable*>& getParameters() const { return parameters_; }
    void addParameter(Variable* param) { parameters_.push_back(param); }
    bool addParameter(Variable* param, SignatureSource source);

    const std::vector<Variable*>& getLocalVariables() const { return localVariables_; }
    void addLocalVariable(Variable* var) { localVariables_.push_back(var); }

    std::vector<Variable*> getAllVariables() const;
    void removeVariable(Variable* var);

    const std::vector<Function*>& getCalledFunctions() const { return calledFunctions_; }
    void addCalledFunction(Function* func) { calledFunctions_.push_back(func); }

    const std::vector<Function*>& getCallingFunctions() const { return callingFunctions_; }
    void addCallingFunction(Function* func) { callingFunctions_.push_back(func); }

    bool isThunk() const { return isThunk_; }
    void setThunk(bool thunk) { isThunk_ = thunk; }

    Function* getThunkedFunction() const { return thunkedFunction_; }
    void setThunkedFunction(Function* func) { thunkedFunction_ = func; }

    bool isExternal() const { return isExternal_; }
    void setExternal(bool external) { isExternal_ = external; }

    bool hasNoReturn() const { return hasNoReturn_; }
    void setHasNoReturn(bool v) { hasNoReturn_ = v; }
    bool setHasNoReturn(bool v, SignatureSource source);

    bool isInline() const { return isInline_; }
    void setInline(bool v) { isInline_ = v; }

    bool isConstructor() const { return isConstructor_; }
    void setConstructor(bool v) { isConstructor_ = v; }

    bool isDestructor() const { return isDestructor_; }
    void setDestructor(bool v) { isDestructor_ = v; }

    int getStackFrameSize() const { return stackFrameSize_; }
    void setStackFrameSize(int size) { stackFrameSize_ = size; }

    StackFrame* getStackFrame() const { return stackFrame_; }
    void setStackFrame(StackFrame* frame) { stackFrame_ = frame; }

    const std::string& getCallFixup() const { return callFixup_; }
    void setCallFixup(const std::string& name) { callFixup_ = name; }

    std::string getSignatureString() const;
    std::string toString() const;

    const std::vector<FunctionTag*>& getTags() const { return tags_; }
    bool addTag(const std::string& name);
    void removeTag(const std::string& name);
    void addTagDirect(FunctionTag* tag) { tags_.push_back(tag); }

private:
    Address entryPoint_;
    AddressSet body_;
    FunctionSignature* signature_ = nullptr;
    PrototypeModel* callingConvention_ = nullptr;
    DataType* returnType_ = nullptr;
    std::vector<Variable*> parameters_;
    std::vector<Variable*> localVariables_;
    std::vector<Function*> calledFunctions_;
    std::vector<Function*> callingFunctions_;
    bool isThunk_ = false;
    Function* thunkedFunction_ = nullptr;
    bool isExternal_ = false;
    bool hasNoReturn_ = false;
    bool isInline_ = false;
    bool isConstructor_ = false;
    bool isDestructor_ = false;
    int stackFrameSize_ = 0;
    std::string callFixup_;
    StackFrame* stackFrame_ = nullptr;
    Program* program_ = nullptr;
    std::vector<FunctionTag*> tags_;
    SignatureSource signatureSource_ = SignatureSource::UNKNOWN;
    SignatureSource returnTypeSource_ = SignatureSource::UNKNOWN;
    SignatureSource callingConventionSource_ = SignatureSource::UNKNOWN;
    SignatureSource paramSource_ = SignatureSource::UNKNOWN;
    SignatureSource noReturnSource_ = SignatureSource::UNKNOWN;
};

} // namespace ghidra
