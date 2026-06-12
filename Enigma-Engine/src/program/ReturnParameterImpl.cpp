#include <ghidra/ReturnParameterImpl.h>

namespace ghidra {

ReturnParameterImpl::ReturnParameterImpl(DataType* dataType, Program* program)
    : ParameterImpl(RETURN_NAME, RETURN_ORDINAL, dataType, VariableStorage::UNASSIGNED_STORAGE, program, SourceType::DEFAULT) {}

ReturnParameterImpl::ReturnParameterImpl(DataType* dataType, VariableStorage storage, Program* program)
    : ParameterImpl(RETURN_NAME, RETURN_ORDINAL, dataType, storage, program, SourceType::DEFAULT) {}

void ReturnParameterImpl::setName(const std::string& name, SourceType source) {
    // Return parameter name is fixed to <RETURN>
}

bool ReturnParameterImpl::isVoidAllowed() const {
    return true;
}

} // namespace ghidra
