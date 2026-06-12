#pragma once
#include <ghidra/LocalVariable.h>
#include <ghidra/VariableImpl.h>

namespace ghidra {

class LocalVariableImpl : public VariableImpl, public LocalVariable {
public:
    LocalVariableImpl(const std::string& name, DataType* dataType, Address address, Program* program);
    LocalVariableImpl(const std::string& name, DataType* dataType, Address address, Program* program, SourceType sourceType);
    LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, Address address, Program* program);
    LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, Address address, Program* program, SourceType sourceType);
    
    LocalVariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program);
    LocalVariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType);
    LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, VariableStorage storage, Program* program);
    LocalVariableImpl(const std::string& name, int firstUseOffset, DataType* dataType, VariableStorage storage, Program* program, SourceType sourceType);

    ~LocalVariableImpl() override = default;

    int getFirstUseOffset() const override;
    bool setFirstUseOffset(int firstUseOffset) override;

private:
    int firstUseOffset_ = 0;
};

} // namespace ghidra
