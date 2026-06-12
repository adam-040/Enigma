#pragma once
#include <ghidra/Parameter.h>
#include <ghidra/VariableImpl.h>
#include <ghidra/PointerDataType.h>

namespace ghidra {

class ParameterImpl : public VariableImpl, virtual public Parameter {
public:
    ParameterImpl(const std::string& name, DataType* dataType, Program* program);
    ParameterImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program);
    ParameterImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType);
    ParameterImpl(const std::string& name, int ordinal, DataType* dataType, VariableStorage storage, Program* program);
    ParameterImpl(const std::string& name, int ordinal, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType);
    ParameterImpl(const std::string& name, DataType* dataType, Address address, Program* program);
    ParameterImpl(const std::string& name, int ordinal, DataType* dataType, Address address, Program* program);
    ParameterImpl(const std::string& name, int ordinal, DataType* dataType, Address address, Program* program, SourceType sourceType);

    ~ParameterImpl() override;

    int getOrdinal() const override;
    bool isAutoParameter() const override;
    AutoParameterType getAutoParameterType() const override;
    bool isForcedIndirect() const override;
    DataType* getFormalDataType() const override;
    int getFirstUseOffset() const override;

    DataType* getDataType() const override;
    void setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) override;
    void setDataType(DataType* type, SourceType source) override;
    void setDataType(DataType* type, bool alignStack, bool force, SourceType source) override;

protected:
    int ordinal_ = UNASSIGNED_ORDINAL;
    mutable PointerDataType* cachedPointerDataType_ = nullptr;

    void clearPointerCache() const;
};

} // namespace ghidra
