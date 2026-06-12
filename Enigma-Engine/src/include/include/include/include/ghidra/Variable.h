#pragma once

#include <ghidra/Address.h>
#include <ghidra/DataType.h>
#include <ghidra/SourceType.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Varnode.h>
#include <ghidra/Register.h>
#include <ghidra/Symbol.h>
#include <string>
#include <vector>

namespace ghidra {

class Function;
class Program;

class Variable {
public:
    virtual ~Variable() = default;

    virtual DataType* getDataType() const = 0;
    virtual void setDataType(DataType* type, VariableStorage storage, bool force, SourceType source) = 0;
    virtual void setDataType(DataType* type, SourceType source) = 0;
    virtual void setDataType(DataType* type, bool alignStack, bool force, SourceType source) = 0;

    virtual std::string getName() const = 0;
    virtual int getLength() const = 0;
    virtual bool isValid() const = 0;
    virtual Function* getFunction() const = 0;
    virtual Program* getProgram() const = 0;
    virtual SourceType getSource() const = 0;

    virtual void setName(const std::string& name, SourceType source) = 0;
    virtual std::string getComment() const = 0;
    virtual void setComment(const std::string& comment) = 0;

    virtual VariableStorage getVariableStorage() const = 0;
    virtual Varnode getFirstStorageVarnode() const = 0;
    virtual Varnode getLastStorageVarnode() const = 0;

    virtual bool isStackVariable() const = 0;
    virtual bool hasStackStorage() const = 0;
    virtual bool isRegisterVariable() const = 0;
    virtual Register* getRegister() const = 0;
    virtual std::vector<Register*> getRegisters() const = 0;
    virtual Address getMinAddress() const = 0;
    virtual int getStackOffset() const = 0;
    virtual bool isMemoryVariable() const = 0;
    virtual bool isUniqueVariable() const = 0;
    virtual bool isCompoundVariable() const = 0;
    virtual bool hasAssignedStorage() const = 0;
    virtual int getFirstUseOffset() const = 0;

    virtual Symbol* getSymbol() const = 0;
    virtual bool isEquivalent(Variable* variable) = 0;

    virtual std::string toString() const = 0;
};

} // namespace ghidra
