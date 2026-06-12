#pragma once
#include <ghidra/ParameterImpl.h>
#include <ghidra/AutoParameterType.h>

namespace ghidra {

class AutoParameterImpl : public ParameterImpl {
public:
    AutoParameterImpl(DataType* dataType, VariableStorage storage, AutoParameterType type, Program* program);
    AutoParameterImpl(DataType* dataType, int ordinal, VariableStorage storage, AutoParameterType type, Program* program);

    ~AutoParameterImpl() override = default;

    bool isAutoParameter() const override;
    AutoParameterType getAutoParameterType() const override;

    void setName(const std::string& name, SourceType source) override;
    void setComment(const std::string& comment) override;
    void setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) override;
    void setDataType(DataType* type, SourceType source) override;
    void setDataType(DataType* type, bool alignStack, bool force, SourceType source) override;

private:
    AutoParameterType autoType_;
};

} // namespace ghidra
