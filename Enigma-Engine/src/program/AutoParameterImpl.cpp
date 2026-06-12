#include <ghidra/AutoParameterImpl.h>
#include <stdexcept>

namespace ghidra {

AutoParameterImpl::AutoParameterImpl(DataType* dataType, VariableStorage storage, AutoParameterType type, Program* program)
    : ParameterImpl(getDisplayName(type), UNASSIGNED_ORDINAL, dataType, storage, program, SourceType::DEFAULT), autoType_(type) {}

AutoParameterImpl::AutoParameterImpl(DataType* dataType, int ordinal, VariableStorage storage, AutoParameterType type, Program* program)
    : ParameterImpl(getDisplayName(type), ordinal, dataType, storage, program, SourceType::DEFAULT), autoType_(type) {}

bool AutoParameterImpl::isAutoParameter() const {
    return true;
}

AutoParameterType AutoParameterImpl::getAutoParameterType() const {
    return autoType_;
}

void AutoParameterImpl::setName(const std::string& name, SourceType source) {
    throw std::runtime_error("Auto-parameter is read-only");
}

void AutoParameterImpl::setComment(const std::string& comment) {
    throw std::runtime_error("Auto-parameter is read-only");
}

void AutoParameterImpl::setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) {
    throw std::runtime_error("Auto-parameter is read-only");
}

void AutoParameterImpl::setDataType(DataType* type, SourceType source) {
    throw std::runtime_error("Auto-parameter is read-only");
}

void AutoParameterImpl::setDataType(DataType* type, bool alignStack, bool force, SourceType source) {
    throw std::runtime_error("Auto-parameter is read-only");
}

} // namespace ghidra
