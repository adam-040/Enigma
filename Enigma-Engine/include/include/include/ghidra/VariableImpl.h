#pragma once

#include <ghidra/Variable.h>
#include <ghidra/SourceType.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/DataType.h>
#include <ghidra/Register.h>
#include <ghidra/Program.h>
#include <ghidra/Varnode.h>
#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <optional>

namespace ghidra {

class VariableImpl : virtual public Variable {
public:
    virtual ~VariableImpl() = default;

    DataType* getDataType() const override;
    void setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) override;
    void setDataType(DataType* type, SourceType source) override;
    void setDataType(DataType* type, bool alignStack, bool force, SourceType source) override;

    std::string getName() const override;
    int getLength() const override;
    bool isValid() const override;
    Function* getFunction() const override;
    Program* getProgram() const override;
    SourceType getSource() const override;

    void setName(const std::string& name, SourceType source) override;
    std::string getComment() const override;
    void setComment(const std::string& comment) override;

    VariableStorage getVariableStorage() const override;
    Varnode getFirstStorageVarnode() const override;
    Varnode getLastStorageVarnode() const override;

    bool isStackVariable() const override;
    bool hasStackStorage() const override;
    bool isRegisterVariable() const override;
    Register* getRegister() const override;
    std::vector<Register*> getRegisters() const override;
    Address getMinAddress() const override;
    int getStackOffset() const override;
    int getFirstUseOffset() const override;
    bool isMemoryVariable() const override;
    bool isUniqueVariable() const override;
    bool isCompoundVariable() const override;
    bool hasAssignedStorage() const override;

    Symbol* getSymbol() const override;
    bool isEquivalent(Variable* variable) override;

    std::string toString() const override;

    // Public constructors (some protected ones exist below)
    VariableImpl(const std::string& name, DataType* dataType, int stackOffset, Program* program, SourceType sourceType);

protected:
    // Constructors
    VariableImpl(const std::string& name, DataType* dataType, Program* program, SourceType sourceType);
    VariableImpl(const std::string& name, DataType* dataType, Address storageAddr, Program* program, SourceType sourceType);
    VariableImpl(const std::string& name, DataType* dataType, Register* registerStorage, Program* program, SourceType sourceType);
    VariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, bool force, Program* program, SourceType sourceType);

    VariableImpl(const std::string& name, DataType* dataType, VariableStorage storage, Address storageAddr,
                 std::optional<int> stackOffset, Register* registerStorage, bool force, Program* program,
                 SourceType sourceType);

    virtual bool hasDefaultName() const;
    virtual bool isVoidAllowed() const;

    std::string name_;
    DataType* dataType_ = nullptr;
    std::string comment_;
    SourceType sourceType_ = SourceType::DEFAULT;
    VariableStorage variableStorage_;
    Program* program_ = nullptr;

private:
    static void checkUsage(const VariableStorage& storage, Address storageAddr, std::optional<int> stackOffset, Register* registerStorage);
    static void checkProgram(Program* program);
    VariableStorage computeStorage(Address storageAddr) const;
    VariableStorage resizeStorage(const VariableStorage& curStorage, DataType* type) const;
    VariableStorage shrinkStorage(const VariableStorage& curStorage, int newSize, DataType* type) const;
    VariableStorage expandStorage(const VariableStorage& curStorage, int newSize, DataType* type) const;
    Varnode shrinkVarnode(const Varnode& varnode, int sizeReduction, const VariableStorage& curStorage, int newSize, DataType* type) const;
    Varnode expandVarnode(const Varnode& varnode, int sizeIncrease, const VariableStorage& curStorage, int newSize, DataType* type) const;
    Varnode resizeStackVarnode(const Varnode& varnode, int newVarnodeSize, const VariableStorage& curStorage, int newSize, DataType* type) const;
};

} // namespace ghidra
