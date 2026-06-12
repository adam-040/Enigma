#include <ghidra/VariableImpl.h>
#include <ghidra/VariableUtilities.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/Parameter.h>
#include <stdexcept>
#include <sstream>
#include <algorithm>

namespace ghidra {

VariableImpl::VariableImpl(const std::string& name, DataType* dataType, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, VariableStorage::UNASSIGNED_STORAGE, Address(), std::nullopt, nullptr, false, program, sourceType) {}

VariableImpl::VariableImpl(const std::string& name, DataType* dataType, int stackOffset, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, VariableStorage::UNASSIGNED_STORAGE, Address(), stackOffset, nullptr, false, program, sourceType) {}

VariableImpl::VariableImpl(const std::string& name, DataType* dataType, Address storageAddr, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, VariableStorage::UNASSIGNED_STORAGE, storageAddr, std::nullopt, nullptr, false, program, sourceType) {}

VariableImpl::VariableImpl(const std::string& name, DataType* dataType, Register* registerStorage, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, VariableStorage::UNASSIGNED_STORAGE, Address(), std::nullopt, registerStorage, false, program, sourceType) {}

VariableImpl::VariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, bool force, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, storage, Address(), std::nullopt, nullptr, force, program, sourceType) {}

VariableImpl::VariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, Address storageAddr,
                           std::optional<int> stackOffset, Register* registerStorage, bool force, Program* program,
                           SourceType sourceType) {
    checkUsage(storage, storageAddr, stackOffset, registerStorage);
    checkProgram(program);

    program_ = program;
    name_ = name;

    if (storage.isUnassignedStorage()) {
        if (registerStorage != nullptr) {
            dataType_ = VariableUtilities::checkDataType(dataType, false, registerStorage->getMinimumByteSize(), program);
            int size = dataType_->getLength();
            storageAddr = registerStorage->getAddress();
            int regSize = registerStorage->getMinimumByteSize();
            if (regSize < size) {
                if (!force) {
                    throw std::invalid_argument("Register size too small for specified data type size");
                }
                variableStorage_ = VariableStorage(program, {registerStorage});
                return;
            }
            else if (registerStorage->isBigEndian() && regSize > size) {
                storageAddr = storageAddr.add(regSize - size);
            }
        }
        else {
            if (stackOffset.has_value()) {
                const AddressSpace* stackSpace = program->getAddressFactory()->getStackSpace();
                storageAddr = Address(const_cast<AddressSpace*>(stackSpace), stackOffset.value());
            }
            dataType_ = VariableUtilities::checkDataType(dataType, !storageAddr.isValid() && isVoidAllowed(), 1, program);
        }
        variableStorage_ = computeStorage(storageAddr);
    }
    else {
        dataType_ = VariableUtilities::checkDataType(dataType, (storage.isVoidStorage() || storage.isUnassignedStorage()) && isVoidAllowed(), storage.size(), program);
        VariableUtilities::checkStorage(storage, dataType_, force);
        variableStorage_ = storage;
    }

    sourceType_ = hasDefaultName() ? SourceType::DEFAULT : sourceType;
}

void VariableImpl::checkUsage(const VariableStorage& storage, Address storageAddr, std::optional<int> stackOffset, Register* registerStorage) {
    bool invalidUsage = false;
    if (!storage.isUnassignedStorage()) {
        invalidUsage = storageAddr.isValid() || stackOffset.has_value() || registerStorage != nullptr;
    }
    else if (registerStorage != nullptr) {
        invalidUsage = storageAddr.isValid() || stackOffset.has_value();
    }
    else if (stackOffset.has_value()) {
        invalidUsage = storageAddr.isValid();
    }
    if (invalidUsage) {
        throw std::invalid_argument("Only one storage location may be specified");
    }
}

void VariableImpl::checkProgram(Program* program) {
    if (program == nullptr) {
        throw std::invalid_argument("An open program object is required");
    }
}

VariableStorage VariableImpl::computeStorage(Address storageAddr) const {
    if (!storageAddr.isValid()) {
        return VariableStorage::UNASSIGNED_STORAGE;
    }
    if (!storageAddr.isMemoryAddress() && !storageAddr.isRegisterAddress() &&
        !storageAddr.isStackAddress() && !storageAddr.isHashAddress()) {
        throw std::invalid_argument("Invalid storage address specified");
    }
    int dtLength = dataType_->getLength();
    if (!storageAddr.isStackAddress()) {
        return VariableStorage(program_, storageAddr, dtLength);
    }

    long stackOffset = storageAddr.getOffset();
    if (stackOffset < 0 && -stackOffset < dtLength) {
        throw std::invalid_argument("Data type does not fit within stack frame constraints");
    }
    return VariableStorage(program_, {Varnode(storageAddr, dtLength)});
}

bool VariableImpl::hasDefaultName() const {
    return false;
}

bool VariableImpl::isVoidAllowed() const {
    return false;
}

bool VariableImpl::isValid() const {
    if (VoidDataType::isVoidDataType(dataType_)) {
        return isVoidAllowed() && variableStorage_.isVoidStorage();
    }
    if (dataType_->getLength() <= 0 || !variableStorage_.isValid()) {
        return false;
    }
    return variableStorage_.size() >= dataType_->getLength();
}

std::string VariableImpl::getComment() const {
    return comment_;
}

DataType* VariableImpl::getDataType() const {
    return dataType_;
}

void VariableImpl::setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) {
    type = VariableUtilities::checkDataType(type, (storage.isVoidStorage() || storage.isUnassignedStorage()) && isVoidAllowed(), storage.size(), program_);
    VariableUtilities::checkStorage(storage, type, force);
    dataType_ = type;
    variableStorage_ = storage;
}

void VariableImpl::setDataType(DataType* type, bool align, bool force, SourceType source) {
    setDataType(type, SourceType::ANALYSIS);
}

void VariableImpl::setDataType(DataType* type, SourceType source) {
    type = VariableUtilities::checkDataType(type, isVoidAllowed(), dataType_->getLength(), program_);
    variableStorage_ = VoidDataType::isVoidDataType(type) ? VariableStorage::VOID_STORAGE
                                                          : resizeStorage(variableStorage_, type);
    dataType_ = type;
}

Function* VariableImpl::getFunction() const {
    return nullptr;
}

Program* VariableImpl::getProgram() const {
    return program_;
}

int VariableImpl::getLength() const {
    return dataType_->getLength();
}

std::string VariableImpl::getName() const {
    return name_;
}

SourceType VariableImpl::getSource() const {
    return sourceType_;
}

Symbol* VariableImpl::getSymbol() const {
    return nullptr;
}

void VariableImpl::setComment(const std::string& comment) {
    std::string cleanComment = comment;
    if (!cleanComment.empty() && cleanComment.back() == '\n') {
        cleanComment.pop_back();
    }
    comment_ = cleanComment;
}

void VariableImpl::setName(const std::string& name, SourceType source) {
    name_ = name;
    sourceType_ = hasDefaultName() ? SourceType::DEFAULT : source;
}

bool VariableImpl::hasAssignedStorage() const {
    return !variableStorage_.isUnassignedStorage();
}

VariableStorage VariableImpl::getVariableStorage() const {
    return variableStorage_;
}

Varnode VariableImpl::getFirstStorageVarnode() const {
    return variableStorage_.getFirstVarnode();
}

Varnode VariableImpl::getLastStorageVarnode() const {
    return variableStorage_.getLastVarnode();
}

bool VariableImpl::isStackVariable() const {
    return variableStorage_.isStackStorage();
}

bool VariableImpl::hasStackStorage() const {
    return variableStorage_.hasStackStorage();
}

bool VariableImpl::isRegisterVariable() const {
    return variableStorage_.isRegisterStorage();
}

Register* VariableImpl::getRegister() const {
    return variableStorage_.getRegister();
}

std::vector<Register*> VariableImpl::getRegisters() const {
    return variableStorage_.getRegisters();
}

Address VariableImpl::getMinAddress() const {
    return variableStorage_.getMinAddress();
}

int VariableImpl::getStackOffset() const {
    return variableStorage_.getStackOffset();
}

int VariableImpl::getFirstUseOffset() const {
    return 0;
}

bool VariableImpl::isMemoryVariable() const {
    return variableStorage_.isMemoryStorage();
}

bool VariableImpl::isUniqueVariable() const {
    return variableStorage_.isHashStorage();
}

bool VariableImpl::isCompoundVariable() const {
    return variableStorage_.isCompoundStorage();
}

std::string VariableImpl::toString() const {
    std::stringstream ss;
    ss << "[" << dataType_->getName() << " " << getName() << "@" << variableStorage_.toString() << "]";
    return ss.str();
}

bool VariableImpl::isEquivalent(Variable* otherVar) {
    if (otherVar == nullptr) {
        return false;
    }
    if (otherVar == this) {
        return true;
    }
    // Checking types dynamic casts
    bool thisParam = (dynamic_cast<Parameter*>(this) != nullptr);
    bool otherParam = (dynamic_cast<Parameter*>(otherVar) != nullptr);
    if (thisParam != otherParam) {
        return false;
    }
    if (thisParam) {
        auto* p1 = dynamic_cast<Parameter*>(this);
        auto* p2 = dynamic_cast<Parameter*>(otherVar);
        if (p1->getOrdinal() != p2->getOrdinal()) {
            return false;
        }
    }
    if (variableStorage_ != otherVar->getVariableStorage()) {
        return false;
    }
    if (getFirstUseOffset() != otherVar->getFirstUseOffset()) {
        return false;
    }
    if (dataType_->getName() != otherVar->getDataType()->getName() ||
        dataType_->getLength() != otherVar->getDataType()->getLength()) {
        return false;
    }
    return true;
}

VariableStorage VariableImpl::resizeStorage(const VariableStorage& curStorage, DataType* type) const {
    int newSize = type->getLength();
    int curSize = curStorage.size();
    if (curSize == newSize) {
        return curStorage;
    }
    if (curSize == 0 || curStorage.isUniqueStorage() || curStorage.isHashStorage()) {
        throw std::invalid_argument("Current storage cannot be resized");
    }
    if (newSize > curSize) {
        return expandStorage(curStorage, newSize, type);
    }
    return shrinkStorage(curStorage, newSize, type);
}

VariableStorage VariableImpl::shrinkStorage(const VariableStorage& curStorage, int newSize, DataType* type) const {
    std::vector<Varnode> newList;
    int size = 0;
    for (const auto& vn : curStorage.getVarnodes()) {
        size += vn.getSize();
        if (size >= newSize) {
            newList.push_back(shrinkVarnode(vn, size - newSize, curStorage, newSize, type));
            break;
        }
        newList.push_back(vn);
    }
    return VariableStorage(program_, newList);
}

VariableStorage VariableImpl::expandStorage(const VariableStorage& curStorage, int newSize, DataType* type) const {
    std::vector<Varnode> newList = curStorage.getVarnodes();
    newList.back() = expandVarnode(newList.back(), newSize - curStorage.size(), curStorage, newSize, type);
    return VariableStorage(program_, newList);
}

Varnode VariableImpl::shrinkVarnode(const Varnode& varnode, int sizeReduction, const VariableStorage& curStorage,
                                    int newSize, DataType* type) const {
    Address addr = varnode.getAddress();
    if (addr.isStackAddress()) {
        return resizeStackVarnode(varnode, varnode.getSize() - sizeReduction, curStorage, newSize, type);
    }
    bool isRegister = (program_->getRegister(varnode.getAddress(), varnode.getSize()) != nullptr);
    bool bigEndian = (program_->getLanguage() && program_->getLanguage()->isBigEndian());
    // Abstract check for complex type (structure or array)
    bool complexDt = (type->getName().find("struct") != std::string::npos || type->getName().find("[") != std::string::npos);
    if (bigEndian && (isRegister || !complexDt)) {
        return Varnode(varnode.getAddress().add(sizeReduction), varnode.getSize() - sizeReduction);
    }
    return Varnode(varnode.getAddress(), varnode.getSize() - sizeReduction);
}

Varnode VariableImpl::expandVarnode(const Varnode& varnode, int sizeIncrease, const VariableStorage& curStorage,
                                    int newSize, DataType* type) const {
    Address addr = varnode.getAddress();
    if (addr.isStackAddress()) {
        return resizeStackVarnode(varnode, varnode.getSize() + sizeIncrease, curStorage, newSize, type);
    }
    int size = varnode.getSize() + sizeIncrease;
    bool bigEndian = (program_->getLanguage() && program_->getLanguage()->isBigEndian());
    Register* reg = program_->getRegister(varnode.getAddress(), varnode.getSize());
    Address vnAddr = varnode.getAddress();
    if (reg != nullptr) {
        Register* newReg = reg;
        while (newReg->getMinimumByteSize() < size) {
            newReg = newReg->getParentRegister();
            if (newReg == nullptr) {
                throw std::invalid_argument("Current register storage cannot be expanded");
            }
        }
        vnAddr = newReg->getAddress();
        if (bigEndian) {
            vnAddr = vnAddr.add(newReg->getMinimumByteSize() - size);
            return Varnode(vnAddr, size);
        }
    }
    bool complexDt = (type->getName().find("struct") != std::string::npos || type->getName().find("[") != std::string::npos);
    if (bigEndian && !complexDt) {
        return Varnode(vnAddr.subtract(sizeIncrease), size);
    }
    return Varnode(vnAddr, size);
}

Varnode VariableImpl::resizeStackVarnode(const Varnode& varnode, int newVarnodeSize, const VariableStorage& curStorage,
                                         int newSize, DataType* type) const {
    Address curAddr = varnode.getAddress();
    int stackOffset = (int)curAddr.getOffset();
    int newStackOffset = stackOffset;

    int newEndStackOffset = newStackOffset + newVarnodeSize - 1;
    if (newStackOffset < 0 && newEndStackOffset >= 0) {
        throw std::invalid_argument("Data type does not fit within variable stack constraints");
    }

    return Varnode(Address(curAddr.getAddressSpace(), newStackOffset), newVarnodeSize);
}

} // namespace ghidra
