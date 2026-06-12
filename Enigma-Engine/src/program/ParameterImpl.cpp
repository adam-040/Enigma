#include <ghidra/ParameterImpl.h>

namespace ghidra {

ParameterImpl::ParameterImpl(const std::string& name, DataType* dataType, Program* program)
    : VariableImpl(name, dataType, program, SourceType::DEFAULT), ordinal_(UNASSIGNED_ORDINAL) {}

ParameterImpl::ParameterImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program)
    : VariableImpl(name, dataType, storage, false, program, SourceType::DEFAULT), ordinal_(UNASSIGNED_ORDINAL) {}

ParameterImpl::ParameterImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, storage, false, program, sourceType), ordinal_(UNASSIGNED_ORDINAL) {}

ParameterImpl::ParameterImpl(const std::string& name, int ordinal, DataType* dataType, VariableStorage storage, Program* program)
    : VariableImpl(name, dataType, storage, false, program, SourceType::DEFAULT), ordinal_(ordinal) {}

ParameterImpl::ParameterImpl(const std::string& name, int ordinal, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, storage, false, program, sourceType), ordinal_(ordinal) {}

ParameterImpl::ParameterImpl(const std::string& name, DataType* dataType, Address address, Program* program)
    : VariableImpl(name, dataType, address, program, SourceType::DEFAULT), ordinal_(UNASSIGNED_ORDINAL) {}

ParameterImpl::ParameterImpl(const std::string& name, int ordinal, DataType* dataType, Address address, Program* program)
    : VariableImpl(name, dataType, address, program, SourceType::DEFAULT), ordinal_(ordinal) {}

ParameterImpl::ParameterImpl(const std::string& name, int ordinal, DataType* dataType, Address address, Program* program, SourceType sourceType)
    : VariableImpl(name, dataType, address, program, sourceType), ordinal_(ordinal) {}

ParameterImpl::~ParameterImpl() {
    clearPointerCache();
}

int ParameterImpl::getOrdinal() const {
    return ordinal_;
}

bool ParameterImpl::isAutoParameter() const {
    return variableStorage_.isAutoStorage();
}

AutoParameterType ParameterImpl::getAutoParameterType() const {
    return variableStorage_.getAutoParameterType();
}

bool ParameterImpl::isForcedIndirect() const {
    return variableStorage_.isForcedIndirect();
}

DataType* ParameterImpl::getFormalDataType() const {
    return dataType_;
}

int ParameterImpl::getFirstUseOffset() const {
    return 0;
}

DataType* ParameterImpl::getDataType() const {
    if (isForcedIndirect()) {
        if (!cachedPointerDataType_) {
            int ptrLength = variableStorage_.size();
            cachedPointerDataType_ = new PointerDataType(dataType_, ptrLength, nullptr, false);
        }
        return cachedPointerDataType_;
    }
    return dataType_;
}

void ParameterImpl::clearPointerCache() const {
    if (cachedPointerDataType_) {
        delete cachedPointerDataType_;
        cachedPointerDataType_ = nullptr;
    }
}

void ParameterImpl::setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) {
    clearPointerCache();
    VariableImpl::setDataType(type, storage, force, source);
}

void ParameterImpl::setDataType(DataType* type, SourceType source) {
    clearPointerCache();
    VariableImpl::setDataType(type, source);
}

void ParameterImpl::setDataType(DataType* type, bool alignStack, bool force, SourceType source) {
    clearPointerCache();
    VariableImpl::setDataType(type, alignStack, force, source);
}

} // namespace ghidra
