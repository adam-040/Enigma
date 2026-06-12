/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PrototypeModel.h
/// \brief Calling convention prototype model
/// Translated from: ghidra.program.model.lang.PrototypeModel
#pragma once

#include <ghidra/GenericCallingConvention.h>
#include <ghidra/InputListType.h>
#include <ghidra/ParamList.h>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

class Program;
class VariableStorage;
class DataType;
class DataTypeManager;
class PrototypePieces;
class ParameterPieces;

class PrototypeModel {
public:
    static constexpr int UNKNOWN_EXTRAPOP = 0x8000;

    PrototypeModel();
    PrototypeModel(const std::string& name, const std::string& callingConvention,
                   bool isInferred = false);
    explicit PrototypeModel(const std::string& name, PrototypeModel* model);
    virtual ~PrototypeModel() = default;

    const std::string& getName() const { return name_; }
    const std::string& getCallingConvention() const { return callingConvention_; }
    bool isInferred() const { return isInferred_; }
    bool isProgramExtension() const { return isExtension_; }
    void setProgramExtension(bool v) { isExtension_ = v; }

    bool hasThisParameter() const { return hasThisParameter_; }
    void setHasThisParameter(bool v) { hasThisParameter_ = v; }

    bool hasReturnAddressSpace() const { return hasReturnAddressSpace_; }
    void setHasReturnAddressSpace(bool v) { hasReturnAddressSpace_ = v; }

    bool isThisBeforeReturnPointer() const { return thisBeforeReturnPointer_; }
    void setThisBeforeReturnPointer(bool v) { thisBeforeReturnPointer_ = v; }

    int getStackAlignment() const { return stackAlignment_; }
    void setStackAlignment(int align) { stackAlignment_ = align; }

    int getStackParameterAlignment() const;
    void setStackParameterAlignment(int align) { stackParameterAlignment_ = align; }

    int64_t getStackParameterOffset() const;
    void setStackParameterOffset(int offset) { stackParameterOffset_ = offset; }

    int getStackshift() const { return stackshift_; }
    void setStackshift(int shift) { stackshift_ = shift; }

    std::vector<VariableStorage> getStorageLocations(Program* program, const std::vector<DataType*>& dataTypes, bool addAutoParams);

    int getExtraPop() const { return extraPop_; }
    void setExtraPop(int pop) { extraPop_ = pop; }

    bool isNoReturn() const { return noReturn_; }
    void setNoReturn(bool v) { noReturn_ = v; }

    bool isInline() const { return inline_; }
    void setInline(bool v) { inline_ = v; }

    bool isConstructor() const { return isConstructor_; }
    void setConstructor(bool v) { isConstructor_ = v; }

    bool isDestructor() const { return isDestructor_; }
    void setDestructor(bool v) { isDestructor_ = v; }

    virtual bool isErrorPlaceholder() const { return false; }
    virtual bool isMerged() const { return false; }

    InputListType getInputListType() const { return inputListType_; }
    void setInputListType(InputListType t) { inputListType_ = t; }

    bool hasUponEntry() const { return hasUponEntry_; }
    void setHasUponEntry(bool v) { hasUponEntry_ = v; }

    bool hasUponReturn() const { return hasUponReturn_; }
    void setHasUponReturn(bool v) { hasUponReturn_ = v; }

    bool hasInjection() const { return hasUponEntry_ || hasUponReturn_; }

    PrototypeModel* getAliasParent() const { return compatModel_; }
    void setAliasParent(PrototypeModel* model) { compatModel_ = model; }

    ParamList* getInputParams() const { return inputParams_.get(); }
    ParamList* getOutputParams() const { return outputParams_.get(); }
    void setInputParams(std::unique_ptr<ParamList> p) { inputParams_ = std::move(p); }
    void setOutputParams(std::unique_ptr<ParamList> p) { outputParams_ = std::move(p); }

    void buildParamList(const std::string& strategy);

    void assignParameterStorage(PrototypePieces& proto, DataTypeManager* dtManager,
                                std::vector<ParameterPieces>& res, bool addAutoParams);

    VariableStorage getReturnLocation(DataType* dataType, Program* program);
    VariableStorage getArgLocation(int argIndex, std::vector<ParameterPieces>* params,
                                  DataType* dataType, Program* program);

    bool possibleInputParamWithSlot(const Address& loc, int size, ParamList::WithSlotRec& res);
    bool possibleOutputParamWithSlot(const Address& loc, int size, ParamList::WithSlotRec& res);

    std::vector<VariableStorage> getPotentialInputRegisterStorage(Program* prog);

    bool isEquivalent(const PrototypeModel& other) const;
    bool operator==(const PrototypeModel& other) const;
    bool operator!=(const PrototypeModel& other) const;

private:
    std::string name_;
    std::string callingConvention_;
    bool isInferred_ = false;
    bool isExtension_ = false;
    bool hasThisParameter_ = false;
    bool hasReturnAddressSpace_ = false;
    bool thisBeforeReturnPointer_ = false;
    int stackAlignment_ = 0;
    int stackParameterAlignment_ = 4;
    int64_t stackParameterOffset_ = 0;
    int stackshift_ = 0;
    int extraPop_ = UNKNOWN_EXTRAPOP;
    bool noReturn_ = false;
    bool inline_ = false;
    bool isConstructor_ = false;
    bool isDestructor_ = false;
    bool hasUponEntry_ = false;
    bool hasUponReturn_ = false;
    InputListType inputListType_ = InputListType::STANDARD;
    std::unique_ptr<ParamList> inputParams_;
    std::unique_ptr<ParamList> outputParams_;
    PrototypeModel* compatModel_ = nullptr;
};

} // namespace ghidra
