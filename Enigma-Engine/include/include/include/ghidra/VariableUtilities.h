#pragma once

#include <ghidra/Variable.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/DataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Function.h>
#include <ghidra/Program.h>
#include <ghidra/GhidraClass.h>
#include <ghidra/Structure.h>
#include <ghidra/VariableSizeException.h>
#include <ghidra/Varnode.h>
#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace ghidra {

class ParameterImpl;

class VariableUtilities {
public:
    static constexpr int MEMORY_PRECEDENCE = 15;
    static constexpr int REGISTER_PRECEDENCE = 13;
    static constexpr int STACK_PRECEDENCE = 14;
    static constexpr int UNIQUE_PRECEDENCE = 16;
    static constexpr int COMPOUND_PRECEDENCE = 11;
    static constexpr int PARAMETER_PRECEDENCE = 10;

    static int getPrecedence(Variable* var);

    static void registerDtmToProgram(DataTypeManager* dtm, Program* program);
    static void unregisterDtmToProgram(DataTypeManager* dtm);
    static Program* getProgramForDtm(DataTypeManager* dtm);

    static bool storageMatches(const std::vector<Variable*>& vars, const std::vector<Variable*>& otherVars);


    static int compare(Variable* v1, Variable* v2);

    static DataType* getAutoDataType(Function* function, DataType* returnDataType, VariableStorage storage);

    static void checkStorage(VariableStorage storage, DataType* dataType, bool allowSizeMismatch);
    static VariableStorage checkStorage(Function* function, VariableStorage storage, DataType* dataType, bool allowSizeMismatch);

    static DataType* checkDataType(DataType* dataType, bool voidOK, int defaultSize, DataTypeManager* dtMgr);
    static DataType* checkDataType(DataType* dataType, bool voidOK, int defaultSize, Program* program);
    static DataType* checkDataType(DataType* dataType, bool voidOK, DataTypeManager* dtMgr);

    static VariableStorage resizeStorage(VariableStorage curStorage, DataType* dataType, bool alignStack, Function* function);

    class VariableConflictHandler {
    public:
        virtual ~VariableConflictHandler() = default;
        virtual bool resolveConflicts(const std::vector<Variable*>& conflicts) = 0;
    };

    static void checkVariableConflict(Function* function, Variable* var, VariableStorage newStorage, bool deleteConflictingVariables);
    static void checkVariableConflict(const std::vector<Variable*>& existingVariables, Variable* var, VariableStorage newStorage, VariableConflictHandler* conflictHandler);

    static std::optional<int> getBaseStackParamOffset(Function* function);

    static ParameterImpl* getThisParameter(Function* function, PrototypeModel* convention);

    static Structure* findOrCreateClassStruct(GhidraClass* classNamespace, DataTypeManager* dataTypeManager);
    static Structure* findOrCreateClassStruct(Function* function);

    static Structure* findExistingClassStruct(GhidraClass* classNamespace, DataTypeManager* dataTypeManager);
    static Structure* findExistingClassStruct(Function* func);

    static bool equivalentVariableArrays(const std::vector<Variable*>& vars1, const std::vector<Variable*>& vars2);
    static bool equivalentVariables(Variable* var1, Variable* var2);

private:
    struct StackAttributes {
        int stackAlign;
        int bias;
        bool rightJustify;
    };

    static StackAttributes getStackAttributes(Function* function);
    static DataType* getPointer(Program* program, DataType* baseType, int ptrSize);
    static VariableStorage shrinkStorage(VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function);
    static VariableStorage expandStorage(VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function);
    static Varnode shrinkVarnode(Varnode varnode, int sizeReduction, VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function);
    static Varnode shrinkRegister(Register* reg, int sizeReduction);
    static Varnode expandVarnode(Varnode varnode, int sizeIncrease, VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function);
    static Varnode resizeStackVarnode(Varnode varnode, int newVarnodeSize, VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function);

    static Structure* createPlaceholderClassStruct(GhidraClass* classNamespace, DataTypeManager* dataTypeManager);
    static void appendVariableStorageDetails(Variable* var, VariableStorage storage, std::string& msg);
    static void generateConflictException(Variable* var, VariableStorage newStorage, const std::vector<Variable*>& conflicts, int maxConflictVarDetails);
};

} // namespace ghidra
