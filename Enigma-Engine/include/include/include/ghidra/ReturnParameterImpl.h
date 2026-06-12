#pragma once
#include <ghidra/ParameterImpl.h>

namespace ghidra {

class ReturnParameterImpl : public ParameterImpl {
public:
    ReturnParameterImpl(DataType* dataType, Program* program);
    ReturnParameterImpl(DataType* dataType, VariableStorage storage, Program* program);

    ~ReturnParameterImpl() override = default;

    void setName(const std::string& name, SourceType source) override;

protected:
    bool isVoidAllowed() const override;
};

} // namespace ghidra
