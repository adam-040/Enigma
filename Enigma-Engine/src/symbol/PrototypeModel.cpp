/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/PrototypeModel.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/ParamListStandardOut.h>
#include <ghidra/ParamListRegisterOut.h>
#include <ghidra/PrototypePieces.h>
#include <ghidra/ParameterPieces.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/Program.h>

namespace ghidra {

static VariableStorage storageFromPieces(ParameterPieces& piece, Program* program) {
    if (!piece.type || VoidDataType::isVoidDataType(piece.type)) {
        return VariableStorage::VOID_STORAGE;
    }
    if (piece.address == Address::NO_ADDRESS) {
        return VariableStorage::UNASSIGNED_STORAGE;
    }
    int sz = piece.type->getLength();
    if (sz == 0) {
        return VariableStorage::UNASSIGNED_STORAGE;
    }
    if (program) {
        return VariableStorage(program, piece.address, sz);
    }
    return VariableStorage::UNASSIGNED_STORAGE;
}

PrototypeModel::PrototypeModel()
    : extraPop_(UNKNOWN_EXTRAPOP), stackshift_(-1) {}

PrototypeModel::PrototypeModel(const std::string& name, const std::string& callingConvention, bool isInferred)
    : name_(name), callingConvention_(callingConvention), isInferred_(isInferred),
      extraPop_(UNKNOWN_EXTRAPOP), stackshift_(-1) {}

PrototypeModel::PrototypeModel(const std::string& name, PrototypeModel* model)
    : name_(name), isExtension_(false) {
    if (model) {
        extraPop_ = model->extraPop_;
        stackshift_ = model->stackshift_;
        inputListType_ = model->inputListType_;
        compatModel_ = model;
        hasThisParameter_ = model->hasThisParameter_ || name == "__thiscall";
        isConstructor_ = model->isConstructor_;
        hasUponEntry_ = model->hasUponEntry_;
        hasUponReturn_ = model->hasUponReturn_;
        if (model->inputParams_) {
            inputParams_.reset(model->inputParams_->clone());
        }
        if (model->outputParams_) {
            outputParams_.reset(model->outputParams_->clone());
        }
    }
}

void PrototypeModel::buildParamList(const std::string& strategy) {
    if (strategy.empty() || strategy == "standard") {
        inputParams_ = std::make_unique<ParamListStandard>();
        outputParams_ = std::make_unique<ParamListStandardOut>();
        inputListType_ = InputListType::STANDARD;
    }
    else if (strategy == "register") {
        inputParams_ = std::make_unique<ParamListStandard>();
        outputParams_ = std::make_unique<ParamListRegisterOut>();
        inputListType_ = InputListType::REGISTER;
    }
}

void PrototypeModel::assignParameterStorage(PrototypePieces& proto, DataTypeManager* dtManager,
                                              std::vector<ParameterPieces>& res, bool addAutoParams) {
    if (outputParams_) {
        outputParams_->assignMap(proto, dtManager, res, addAutoParams);
    }
    if (inputParams_) {
        inputParams_->assignMap(proto, dtManager, res, addAutoParams);
    }
    if (hasThisParameter_ && addAutoParams && res.size() > 1) {
        int thisIndex = 1;
        if (res[1].hiddenReturnPtr && res.size() > 2) {
            if (inputParams_ && inputParams_->isThisBeforeRetPointer()) {
                res[1].swapMarkup(res[2]);
            }
            else {
                thisIndex = 2;
            }
        }
        res[thisIndex].isThisPointer = true;
    }
}

VariableStorage PrototypeModel::getReturnLocation(DataType* dataType, Program* program) {
    if (!dataType) {
        return VariableStorage::UNASSIGNED_STORAGE;
    }
    PrototypePieces proto;
    proto.outtype = dataType;

    std::vector<ParameterPieces> res;
    if (outputParams_) {
        outputParams_->assignMap(proto, program ? program->getDataTypeManager() : nullptr, res, false);
    }
    if (!res.empty()) {
        return storageFromPieces(res[0], program);
    }
    return VariableStorage::UNASSIGNED_STORAGE;
}

VariableStorage PrototypeModel::getArgLocation(int argIndex, std::vector<ParameterPieces>* params,
                                                DataType* dataType, Program* program) {
    DataTypeManager* dtManager = program ? program->getDataTypeManager() : nullptr;
    size_t dataTypeCount = static_cast<size_t>(argIndex) + 2;
    std::vector<DataType*> dataTypes(dataTypeCount);
    dataTypes[0] = &VoidDataType::dataType();    // Assume void return
    for (int i = 0; i < argIndex; ++i) {
        if (params && static_cast<size_t>(i) < params->size()) {
            dataTypes[static_cast<size_t>(i) + 1] = (*params)[i].type;
        }
        else {
            dataTypes[static_cast<size_t>(i) + 1] = nullptr;
        }
    }
    dataTypes[dataTypeCount - 1] = dataType;
    std::vector<VariableStorage> stores = getStorageLocations(program, dataTypes, false);
    return stores.empty() ? VariableStorage::UNASSIGNED_STORAGE : stores.back();
}

std::vector<VariableStorage> PrototypeModel::getStorageLocations(Program* program,
                                                                  const std::vector<DataType*>& dataTypes,
                                                                  bool addAutoParams) {
    std::vector<VariableStorage> result;
    if (dataTypes.empty()) {
        return result;
    }
    DataType* injectedThis = nullptr;
    if (addAutoParams && hasThisParameter_) {
        injectedThis = program ? program->getDataTypeManager()->getPointer(&VoidDataType::dataType()) : nullptr;
    }
    PrototypePieces proto;
    proto.outtype = dataTypes[0];
    for (size_t i = 1; i < dataTypes.size(); ++i) {
        proto.intypes.push_back(dataTypes[i]);
    }
    if (injectedThis) {
        proto.intypes.insert(proto.intypes.begin(), injectedThis);
    }
    std::vector<ParameterPieces> pieces;
    assignParameterStorage(proto, program ? program->getDataTypeManager() : nullptr, pieces, addAutoParams);
    result.reserve(pieces.size());
    for (auto& piece : pieces) {
        result.push_back(storageFromPieces(piece, program));
    }
    return result;
}

bool PrototypeModel::possibleInputParamWithSlot(const Address& loc, int size, ParamList::WithSlotRec& res) {
    if (!inputParams_) return false;
    return inputParams_->possibleParamWithSlot(loc, size, res);
}

bool PrototypeModel::possibleOutputParamWithSlot(const Address& loc, int size, ParamList::WithSlotRec& res) {
    if (!outputParams_) return false;
    return outputParams_->possibleParamWithSlot(loc, size, res);
}

std::vector<VariableStorage> PrototypeModel::getPotentialInputRegisterStorage(Program* prog) {
    if (!inputParams_) return {};
    return inputParams_->getPotentialRegisterStorage(prog);
}

int PrototypeModel::getStackParameterAlignment() const {
    if (inputParams_) {
        return inputParams_->getStackParameterAlignment();
    }
    return stackParameterAlignment_;
}

int64_t PrototypeModel::getStackParameterOffset() const {
    if (inputParams_) {
        return inputParams_->getStackParameterOffset();
    }
    return stackParameterOffset_;
}

bool PrototypeModel::isEquivalent(const PrototypeModel& other) const {
    if (this == &other) return true;
    if (name_ != other.name_) return false;
    if (extraPop_ != other.extraPop_ || stackshift_ != other.stackshift_) return false;
    if (hasThisParameter_ != other.hasThisParameter_ || isConstructor_ != other.isConstructor_) return false;
    if (hasUponEntry_ != other.hasUponEntry_ || hasUponReturn_ != other.hasUponReturn_) return false;
    if (inputListType_ != other.inputListType_) return false;
    if (inputParams_ && other.inputParams_) {
        if (!inputParams_->isEquivalent(other.inputParams_.get())) return false;
    }
    else if (inputParams_ != other.inputParams_) return false;
    if (outputParams_ && other.outputParams_) {
        if (!outputParams_->isEquivalent(other.outputParams_.get())) return false;
    }
    else if (outputParams_ != other.outputParams_) return false;
    return true;
}

bool PrototypeModel::operator==(const PrototypeModel& other) const {
    return name_ == other.name_;
}

bool PrototypeModel::operator!=(const PrototypeModel& other) const {
    return name_ != other.name_;
}

} // namespace ghidra
