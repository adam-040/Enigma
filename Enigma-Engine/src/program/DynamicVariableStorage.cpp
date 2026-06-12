#include <ghidra/DynamicVariableStorage.h>

namespace ghidra {

const DynamicVariableStorage DynamicVariableStorage::INDIRECT_VOID_STORAGE;

DynamicVariableStorage::DynamicVariableStorage()
    : VariableStorage(StorageType::UNASSIGNED), forcedIndirect_(true), isVoid_(true) {}

DynamicVariableStorage::DynamicVariableStorage(std::optional<AutoParameterType> autoParamType)
    : VariableStorage(StorageType::UNASSIGNED), autoParamType_(autoParamType), isUnassigned_(true) {}

DynamicVariableStorage::DynamicVariableStorage(bool forcedIndirect)
    : VariableStorage(StorageType::UNASSIGNED), forcedIndirect_(forcedIndirect), isUnassigned_(true) {}

DynamicVariableStorage::DynamicVariableStorage(Program* program, std::optional<AutoParameterType> autoParamType, Address address, int size)
    : VariableStorage(program, address, size), autoParamType_(autoParamType) {}

DynamicVariableStorage::DynamicVariableStorage(Program* program, std::optional<AutoParameterType> autoParamType, const std::vector<Varnode>& varnodes)
    : VariableStorage(program, varnodes), autoParamType_(autoParamType) {}

DynamicVariableStorage::DynamicVariableStorage(Program* program, bool forcedIndirect, Address address, int size)
    : VariableStorage(program, address, size), forcedIndirect_(forcedIndirect) {}

DynamicVariableStorage::DynamicVariableStorage(Program* program, bool forcedIndirect, const std::vector<Varnode>& varnodes)
    : VariableStorage(program, varnodes), forcedIndirect_(forcedIndirect) {}

bool DynamicVariableStorage::isForcedIndirect() const {
    return forcedIndirect_;
}

bool DynamicVariableStorage::isAutoStorage() const {
    return autoParamType_.has_value();
}

bool DynamicVariableStorage::isUnassignedStorage() const {
    return isUnassigned_;
}

bool DynamicVariableStorage::isVoidStorage() const {
    return isVoid_;
}

AutoParameterType DynamicVariableStorage::getAutoParameterType() const {
    return autoParamType_.value_or(AutoParameterType::THIS);
}

std::string DynamicVariableStorage::toString() const {
    std::string str = VariableStorage::toString();
    if (forcedIndirect_ && !varnodes_.empty()) {
        str += " (ptr)";
    }
    if (autoParamType_.has_value()) {
        str += " (auto)";
    }
    return str;
}

DynamicVariableStorage DynamicVariableStorage::getUnassignedDynamicStorage(std::optional<AutoParameterType> autoParamType) {
    return DynamicVariableStorage(autoParamType);
}

DynamicVariableStorage DynamicVariableStorage::getUnassignedDynamicStorage(bool forcedIndirect) {
    return DynamicVariableStorage(forcedIndirect);
}

} // namespace ghidra
