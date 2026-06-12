#include <ghidra/VariableUtilities.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/DefaultDataType.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Structure.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/AbstractFloatDataType.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/Program.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/Function.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/InvalidInputException.h>
#include <ghidra/Varnode.h>
#include <ghidra/Register.h>
#include <ghidra/CategoryPath.h>
#include <ghidra/GhidraClass.h>
#include <ghidra/FunctionDefinition.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Memory.h>
#include <ghidra/Msg.h>
#include <ghidra/BitFieldDataType.h>

#include <mutex>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <optional>

namespace ghidra {

namespace {

std::mutex dtmMapMutex;
std::unordered_map<DataTypeManager*, Program*> dtmToProgramMap;

class UndefinedDataType : public AbstractDataType {
private:
    int length_;
public:
    UndefinedDataType(int length, DataTypeManager* dtm = nullptr)
        : AbstractDataType(CategoryPath::ROOT(), "undefined" + std::to_string(length), dtm), length_(length) {}

    std::string getMnemonic(Settings* settings) const override {
        return "undef" + std::to_string(length_);
    }

    int getLength() const override {
        return length_;
    }

    int getAlignedLength() const override {
        return length_;
    }

    std::string getDescription() const override {
        return "undefined " + std::to_string(length_) + "-byte datatype";
    }

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override {
        return "";
    }

    const std::type_info& getValueClass(Settings* settings) const override {
        return typeid(void);
    }

    DataType* clone(DataTypeManager* dtm) const override {
        if (dtm == getDataTypeManager()) {
            return const_cast<UndefinedDataType*>(this);
        }
        return new UndefinedDataType(length_, dtm);
    }

    DataType* copy(DataTypeManager* dtm) const override {
        return new UndefinedDataType(length_, dtm);
    }

    bool isEquivalent(const DataType* dt) const override {
        if (!dt) return false;
        auto* other = dynamic_cast<const UndefinedDataType*>(dt);
        return other && other->length_ == length_;
    }

    int getAlignment() const override {
        return 1;
    }

    std::vector<SettingsDefinition*> getSettingsDefinitions() const override {
        return {};
    }

    Settings* getDefaultSettings() const override {
        return nullptr;
    }
};

DataType* registerOrDelete(DataType* dt, DataTypeManager* dtMgr) {
    if (!dt) return nullptr;
    if (auto* impl = dynamic_cast<DataTypeManagerImpl*>(dtMgr)) {
        DataType* registered = impl->addDataType(dt);
        if (registered != dt) {
            delete dt;
        }
        return registered;
    }
    return dt;
}

DataType* getUndefinedDataType(int size, DataTypeManager* dtm) {
    if (size < 1) {
        return &DefaultDataType::dataType();
    }
    if (size > 8) {
        DataType* undef1 = new UndefinedDataType(1, dtm);
        undef1 = registerOrDelete(undef1, dtm);
        DataType* arrayDt = new ArrayDataType(undef1, size, 1, dtm);
        return registerOrDelete(arrayDt, dtm);
    }
    DataType* undef = new UndefinedDataType(size, dtm);
    return registerOrDelete(undef, dtm);
}

std::vector<std::string> getPathList(Namespace* ns, bool excludeGlobal) {
    std::vector<std::string> list;
    Namespace* curr = ns;
    while (curr) {
        if (excludeGlobal && curr->isGlobal()) {
            break;
        }
        list.push_back(curr->getName());
        curr = curr->getParent();
    }
    std::reverse(list.begin(), list.end());
    return list;
}

struct NamespacePaths {
    std::string namespacePath;
    std::string parentNamespacePath;
    bool isValid = false;
};

NamespacePaths getRelativeCategoryPaths(Namespace* ns) {
    NamespacePaths paths;
    if (!ns || ns->isGlobal()) {
        return paths;
    }
    std::vector<std::string> parentParts = getPathList(ns->getParent(), true);
    std::string parentPath = "";
    for (const auto& part : parentParts) {
        parentPath += CategoryPath::DELIMITER_STRING + CategoryPath::escapeString(part);
    }
    paths.parentNamespacePath = parentPath;
    paths.namespacePath = parentPath + CategoryPath::DELIMITER_STRING + CategoryPath::escapeString(ns->getName());
    paths.isValid = true;
    return paths;
}

enum class CategoryMatchType {
    NONE, SECONDARY, PREFERRED
};

CategoryMatchType getCategoryMatchType(const CategoryPath& categoryPath, const NamespacePaths& namespacePaths, bool parentNamespacePreferred) {
    if (!namespacePaths.isValid) {
        return categoryPath.isRoot() ? CategoryMatchType::PREFERRED : CategoryMatchType::SECONDARY;
    }
    std::string path = categoryPath.getPath();
    if (parentNamespacePreferred && !namespacePaths.parentNamespacePath.empty()) {
        if (path.size() >= namespacePaths.parentNamespacePath.size() &&
            path.compare(path.size() - namespacePaths.parentNamespacePath.size(), namespacePaths.parentNamespacePath.size(), namespacePaths.parentNamespacePath) == 0) {
            return CategoryMatchType::PREFERRED;
        }
    }
    if (!namespacePaths.namespacePath.empty()) {
        if (path.size() >= namespacePaths.namespacePath.size() &&
            path.compare(path.size() - namespacePaths.namespacePath.size(), namespacePaths.namespacePath.size(), namespacePaths.namespacePath) == 0) {
            return parentNamespacePreferred ? CategoryMatchType::SECONDARY : CategoryMatchType::PREFERRED;
        }
    }
    return CategoryMatchType::NONE;
}

template <typename T>
T* findDataType(DataTypeManager* dataTypeManager, const std::string& dtName, std::function<CategoryMatchType(const CategoryPath&)> matcher) {
    std::vector<DataType*> allTypes = dataTypeManager->getDataTypes();
    std::vector<DataType*> matches;
    for (auto* dt : allTypes) {
        if (dt && dt->getName() == dtName) {
            matches.push_back(dt);
        }
    }
    std::sort(matches.begin(), matches.end(), [](DataType* a, DataType* b) {
        std::string pathA = a->getCategoryPath().getPath();
        std::string pathB = b->getCategoryPath().getPath();
        if (pathA.length() != pathB.length()) {
            return pathA.length() < pathB.length();
        }
        return pathA < pathB;
    });
    T* secondaryMatch = nullptr;
    for (auto* dt : matches) {
        T* casted = dynamic_cast<T*>(dt);
        if (!casted) {
            continue;
        }
        CategoryMatchType matchType = matcher(dt->getCategoryPath());
        if (matchType == CategoryMatchType::PREFERRED) {
            return casted;
        }
        if (!secondaryMatch && matchType == CategoryMatchType::SECONDARY) {
            secondaryMatch = casted;
        }
    }
    return secondaryMatch;
}

std::optional<CategoryPath> getPreferredRootNamespaceCategoryPath(DataTypeManager* dataTypeManager) {
    Program* prog = VariableUtilities::getProgramForDtm(dataTypeManager);
    if (prog) {
        return prog->getPreferredRootNamespaceCategoryPath();
    }
    return std::nullopt;
}

template <typename T>
T* getAssignableDataType(DataTypeManager* dataTypeManager, const CategoryPath& rootPath, const std::vector<std::string>* namespacePath, const std::string& dtName) {
    CategoryPath categoryPath = rootPath;
    if (namespacePath && !namespacePath->empty()) {
        categoryPath = CategoryPath(rootPath, *namespacePath);
    }
    DataType* dt = dataTypeManager->getDataType(categoryPath, dtName);
    if (dt) {
        T* casted = dynamic_cast<T*>(dt);
        if (casted) {
            return casted;
        }
    }
    return nullptr;
}

template <typename T>
T* findPreferredDataType(DataTypeManager* dataTypeManager, Namespace* ns, const std::string& dtName, bool parentNamespacePreferred) {
    auto rootPathOpt = getPreferredRootNamespaceCategoryPath(dataTypeManager);
    if (!rootPathOpt.has_value()) {
        return nullptr;
    }
    CategoryPath rootPath = rootPathOpt.value();
    if (!ns || ns->isGlobal()) {
        return getAssignableDataType<T>(dataTypeManager, rootPath, nullptr, dtName);
    }
    if (parentNamespacePreferred) {
        std::vector<std::string> parentParts = getPathList(ns->getParent(), true);
        T* dt = getAssignableDataType<T>(dataTypeManager, rootPath, &parentParts, dtName);
        if (dt) {
            return dt;
        }
    }
    std::vector<std::string> parts = getPathList(ns, true);
    return getAssignableDataType<T>(dataTypeManager, rootPath, &parts, dtName);
}

CategoryPath getDataTypeCategoryPath(const CategoryPath& baseCategory, Namespace* ns) {
    std::vector<std::string> parts = getPathList(ns, true);
    if (parts.empty()) {
        return baseCategory;
    }
    return CategoryPath(baseCategory, parts);
}

} // namespace

void VariableUtilities::registerDtmToProgram(DataTypeManager* dtm, Program* program) {
    std::lock_guard<std::mutex> lock(dtmMapMutex);
    dtmToProgramMap[dtm] = program;
}

void VariableUtilities::unregisterDtmToProgram(DataTypeManager* dtm) {
    std::lock_guard<std::mutex> lock(dtmMapMutex);
    dtmToProgramMap.erase(dtm);
}

Program* VariableUtilities::getProgramForDtm(DataTypeManager* dtm) {
    std::lock_guard<std::mutex> lock(dtmMapMutex);
    auto it = dtmToProgramMap.find(dtm);
    if (it != dtmToProgramMap.end()) {
        return it->second;
    }
    return nullptr;
}

int VariableUtilities::getPrecedence(Variable* var) {
    int precedence = 0;
    if (var->isMemoryVariable()) {
        precedence = MEMORY_PRECEDENCE;
    }
    else if (var->isRegisterVariable()) {
        precedence = REGISTER_PRECEDENCE;
    }
    else if (var->isStackVariable()) {
        precedence = STACK_PRECEDENCE;
    }
    else if (var->isUniqueVariable()) {
        precedence = UNIQUE_PRECEDENCE;
    }
    else if (var->isCompoundVariable()) {
        precedence = COMPOUND_PRECEDENCE;
    }
    else {
        precedence = 0;
    }
    if (dynamic_cast<Parameter*>(var) != nullptr) {
        precedence -= PARAMETER_PRECEDENCE;
    }
    return precedence;
}

bool VariableUtilities::storageMatches(const std::vector<Variable*>& vars, const std::vector<Variable*>& otherVars) {
    if (otherVars.size() != vars.size()) {
        return false;
    }
    for (size_t i = 0; i < otherVars.size(); ++i) {
        if (otherVars[i]->getVariableStorage() != vars[i]->getVariableStorage()) {
            return false;
        }
    }
    return true;
}

int VariableUtilities::compare(Variable* v1, Variable* v2) {
    Parameter* p1 = dynamic_cast<Parameter*>(v1);
    Parameter* p2 = dynamic_cast<Parameter*>(v2);
    if (p1 && p2) {
        return p1->getOrdinal() - p2->getOrdinal();
    }
    int diff = getPrecedence(v1) - getPrecedence(v2);
    if (diff != 0) {
        return diff;
    }
    
    VariableStorage otherStorage = v2->getVariableStorage();
    VariableStorage variableStorage = v1->getVariableStorage();

    if (v1->isStackVariable() && v2->isStackVariable()) {
        diff = v2->getStackOffset() - v1->getStackOffset();
        if (diff != 0) {
            return diff;
        }
    }

    diff = v1->getFirstUseOffset() - v2->getFirstUseOffset();
    if (diff != 0) {
        if (v1->getFirstUseOffset() == 0) {
            return -1;
        }
        if (v2->getFirstUseOffset() == 0) {
            return 1;
        }
        return diff;
    }

    return variableStorage.compareTo(otherStorage);
}

DataType* VariableUtilities::getAutoDataType(Function* function, DataType* returnDataType, VariableStorage storage) {
    AutoParameterType autoParameterType = storage.getAutoParameterType();
    DataTypeManager* dtMgr = function->getProgram()->getDataTypeManager();
    if (autoParameterType == AutoParameterType::THIS) {
        DataType* classStruct = findOrCreateClassStruct(function);
        if (!classStruct) {
            classStruct = &VoidDataType::dataType();
        }
        return getPointer(function->getProgram(), classStruct, storage.size());
    }
    else if (autoParameterType == AutoParameterType::RETURN_STORAGE_PTR) {
        return getPointer(function->getProgram(), returnDataType, storage.size());
    }
    return getUndefinedDataType(storage.size(), dtMgr);
}

DataType* VariableUtilities::getPointer(Program* program, DataType* baseType, int ptrSize) {
    DataTypeManager* dtMgr = program->getDataTypeManager();
    PointerDataType* ptr = new PointerDataType(baseType, ptrSize, dtMgr);
    return registerOrDelete(ptr, dtMgr);
}

void VariableUtilities::checkStorage(VariableStorage storage, DataType* dataType, bool allowSizeMismatch) {
    checkStorage(nullptr, storage, dataType, allowSizeMismatch);
}

VariableStorage VariableUtilities::checkStorage(Function* function, VariableStorage storage, DataType* dataType, bool allowSizeMismatch) {
    if (!storage.isValid()) {
        return storage;
    }
    DataType* baseType = dataType;
    if (auto* td = dynamic_cast<TypeDef*>(baseType)) {
        baseType = td->getBaseDataType();
    }
    int storageSize = storage.size();
    int dtLen = dataType->getLength();
    if (dynamic_cast<VoidDataType*>(baseType) != nullptr) {
        storage = VariableStorage::VOID_STORAGE;
    }
    else if (storage.isUniqueStorage() || storage.isConstantStorage()) {
        throw InvalidInputException("Invalid storage address specified: " + storage.toString());
    }
    else if (dtLen == 0 && (dynamic_cast<Structure*>(baseType) != nullptr)) {
        storage = VariableStorage::UNASSIGNED_STORAGE;
    }
    else if (!allowSizeMismatch && storageSize != dtLen) {
        if (dynamic_cast<AbstractFloatDataType*>(dataType) != nullptr) {
            return storage;
        }
        if (function != nullptr) {
            return resizeStorage(storage, dataType, true, function);
        }
        if (dtLen < storageSize && storage.isRegisterStorage()) {
            return VariableStorage(storage.getProgram(), std::vector<Varnode>{shrinkRegister(storage.getRegister(), storageSize - dtLen)});
        }
        throw InvalidInputException("Storage size does not match data type size: " + std::to_string(dataType->getLength()));
    }
    return storage;
}

DataType* VariableUtilities::checkDataType(DataType* dataType, bool voidOK, int defaultSize, DataTypeManager* dtMgr) {
    if (!dataType) {
        dataType = getUndefinedDataType(defaultSize, dtMgr);
    }
    else if (dynamic_cast<BitFieldDataType*>(dataType) != nullptr) {
        throw InvalidInputException("Bitfield not permitted");
    }
    
    DataType* baseType = dataType;
    if (auto* td = dynamic_cast<TypeDef*>(baseType)) {
        baseType = td->getBaseDataType();
    }
    
    if (dynamic_cast<FunctionDefinition*>(baseType) != nullptr) {
        DataType* ptr = new PointerDataType(dataType, dtMgr);
        dataType = registerOrDelete(ptr, dtMgr);
    }
    else if (auto* arr = dynamic_cast<Array*>(baseType)) {
        if (arr->getNumElements() == 0) {
            DataType* ptr = new PointerDataType(arr->getDataType(), dtMgr);
            dataType = registerOrDelete(ptr, dtMgr);
        }
    }
    
    if (dataType) {
        DataType* cloned = dataType->clone(dtMgr);
        dataType = registerOrDelete(cloned, dtMgr);
    }
    
    if (dynamic_cast<VoidDataType*>(baseType) != nullptr) {
        if (!voidOK) {
            throw InvalidInputException("The void type is not permitted - allowed for function return use only");
        }
        return dataType;
    }
    
    if (dataType && dataType->getLength() <= 0) {
        throw std::invalid_argument("Unsupported data type length (" + std::to_string(dataType->getLength()) + "): " + dataType->getName());
    }
    return dataType;
}

DataType* VariableUtilities::checkDataType(DataType* dataType, bool voidOK, int defaultSize, Program* program) {
    return checkDataType(dataType, voidOK, defaultSize, program->getDataTypeManager());
}

DataType* VariableUtilities::checkDataType(DataType* dataType, bool voidOK, DataTypeManager* dtMgr) {
    return checkDataType(dataType, voidOK, -1, dtMgr);
}

VariableStorage VariableUtilities::resizeStorage(VariableStorage curStorage, DataType* dataType, bool alignStack, Function* function) {
    if (auto* td = dynamic_cast<TypeDef*>(dataType)) {
        dataType = td->getBaseDataType();
    }
    if (dynamic_cast<VoidDataType*>(dataType) != nullptr) {
        return VariableStorage::VOID_STORAGE;
    }
    if (dynamic_cast<AbstractFloatDataType*>(dataType) != nullptr) {
        return curStorage;
    }
    if (!curStorage.isValid()) {
        return curStorage;
    }
    int newSize = dataType->getLength();
    int curSize = curStorage.size();
    if (curSize == newSize) {
        return curStorage;
    }
    if (curSize == 0 || curStorage.isUniqueStorage() || curStorage.isHashStorage()) {
        throw InvalidInputException("Storage can't be resized: " + curStorage.toString());
    }
    if (newSize > curSize) {
        return expandStorage(curStorage, newSize, dataType, alignStack, function);
    }
    return shrinkStorage(curStorage, newSize, dataType, alignStack, function);
}

VariableStorage VariableUtilities::shrinkStorage(VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function) {
    Program* program = function->getProgram();
    std::vector<Varnode> newList;
    int size = 0;
    for (Varnode vn : curStorage.getVarnodes()) {
        size += vn.getSize();
        if (size >= newSize) {
            newList.push_back(shrinkVarnode(vn, size - newSize, curStorage, newSize, dataType, alignStack, function));
            break;
        }
        newList.push_back(vn);
    }
    return VariableStorage(program, newList);
}

VariableStorage VariableUtilities::expandStorage(VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function) {
    Program* program = function->getProgram();
    std::vector<Varnode> varnodes = curStorage.getVarnodes();
    int lastIndex = varnodes.size() - 1;
    varnodes[lastIndex] = expandVarnode(varnodes[lastIndex], newSize - curStorage.size(), curStorage, newSize, dataType, alignStack, function);
    return VariableStorage(program, varnodes);
}

Varnode VariableUtilities::shrinkVarnode(Varnode varnode, int sizeReduction, VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function) {
    Address addr = varnode.getAddress();
    if (addr.isStackAddress()) {
        return resizeStackVarnode(varnode, varnode.getSize() - sizeReduction, curStorage, newSize, dataType, alignStack, function);
    }
    bool isRegister = function->getProgram()->getRegister(varnode.getAddress(), varnode.getSize()) != nullptr;
    bool bigEndian = function->getProgram()->getMemory()->isBigEndian();
    bool complexDt = (dynamic_cast<Composite*>(dataType) != nullptr) || (dynamic_cast<Array*>(dataType) != nullptr);
    if (bigEndian && (isRegister || !complexDt)) {
        return Varnode(varnode.getAddress().add(sizeReduction), varnode.getSize() - sizeReduction);
    }
    return Varnode(varnode.getAddress(), varnode.getSize() - sizeReduction);
}

Varnode VariableUtilities::shrinkRegister(Register* reg, int sizeReduction) {
    bool bigEndian = reg->isBigEndian();
    if (bigEndian) {
        return Varnode(reg->getAddress().add(sizeReduction), reg->getMinimumByteSize() - sizeReduction);
    }
    return Varnode(reg->getAddress(), reg->getMinimumByteSize() - sizeReduction);
}

Varnode VariableUtilities::expandVarnode(Varnode varnode, int sizeIncrease, VariableStorage curStorage, int newSize, DataType* dataType, bool alignStack, Function* function) {
    Address addr = varnode.getAddress();
    if (addr.isStackAddress()) {
        return resizeStackVarnode(varnode, varnode.getSize() + sizeIncrease, curStorage, newSize, dataType, alignStack, function);
    }
    int size = varnode.getSize() + sizeIncrease;
    bool bigEndian = function->getProgram()->getMemory()->isBigEndian();
    Register* reg = function->getProgram()->getRegister(varnode.getAddress(), varnode.getSize());
    Address vnAddr = varnode.getAddress();
    if (reg != nullptr) {
        Register* newReg = reg;
        while (newReg->getMinimumByteSize() < size) {
            newReg = newReg->getParentRegister();
            if (newReg == nullptr) {
                throw InvalidInputException("Storage can't be expanded to " + std::to_string(newSize) + " bytes: " + curStorage.toString());
            }
        }
        vnAddr = newReg->getAddress();
        if (bigEndian) {
            vnAddr = vnAddr.add(newReg->getMinimumByteSize() - size);
            return Varnode(vnAddr, size);
        }
    }
    bool complexDt = (dynamic_cast<Composite*>(dataType) != nullptr) || (dynamic_cast<Array*>(dataType) != nullptr);
    if (bigEndian && !complexDt) {
        return Varnode(vnAddr.subtract(sizeIncrease), size);
    }
    return Varnode(vnAddr, size);
}

Varnode VariableUtilities::resizeStackVarnode(Varnode varnode, int newVarnodeSize, VariableStorage curStorage, int newSize, DataType* dataType, bool align, Function* function) {
    bool complexDt = (dynamic_cast<Composite*>(dataType) != nullptr) || (dynamic_cast<Array*>(dataType) != nullptr);
    StackAttributes stackAttributes = getStackAttributes(function);
    Address curAddr = varnode.getAddress();
    int stackOffset = (int)curAddr.getOffset();
    int newStackOffset = stackOffset;

    if (stackAttributes.rightJustify && align) {
        int stackAlign = stackAttributes.stackAlign;
        if ((stackOffset + varnode.getSize() - stackAttributes.bias) % stackAlign != 0) {
            stackAlign = 1;
        }
        int newAlign = (newStackOffset - stackAttributes.bias) % stackAlign;
        if (newAlign < 0) {
            newAlign += stackAlign;
        }
        newStackOffset -= newAlign;
        if (!complexDt) {
            int cellExcess = newVarnodeSize % stackAlign;
            if (cellExcess != 0) {
                newStackOffset += stackAlign - cellExcess;
            }
        }
    }

    int newEndStackOffset = newStackOffset + newVarnodeSize - 1;
    if (newStackOffset < 0 && newEndStackOffset >= 0) {
        throw InvalidInputException("Data type does not fit within variable stack constraints");
    }
    return Varnode(Address(curAddr.getAddressSpace(), newStackOffset), newVarnodeSize);
}

VariableUtilities::StackAttributes VariableUtilities::getStackAttributes(Function* function) {
    CompilerSpec* compilerSpec = function->getProgram()->getCompilerSpec();
    bool rightJustify = compilerSpec->isStackRightJustified();
    PrototypeModel* callingConvention = function->getCallingConvention();
    if (callingConvention == nullptr) {
        callingConvention = compilerSpec->getDefaultCallingConvention();
    }
    int stackAlign = callingConvention ? callingConvention->getStackParameterAlignment() : 4;
    if (stackAlign < 0) {
        stackAlign = 1;
    }
    int bias = 0;
    if (callingConvention != nullptr) {
        // callingConvention->getStackParameterOffset() returns long/int in C++
        long stackBase = callingConvention->getStackParameterOffset();
        bias = (int)(stackBase % stackAlign);
        if (bias < 0) {
            bias += stackAlign;
        }
    }
    return StackAttributes{stackAlign, bias, rightJustify};
}

void VariableUtilities::checkVariableConflict(Function* function, Variable* var, VariableStorage newStorage, bool deleteConflictingVariables) {
    if (!newStorage.isValid()) {
        return;
    }
    std::vector<Variable*> conflicts;
    for (Variable* otherVar : function->getAllVariables()) {
        if (otherVar == var) {
            continue;
        }
        if (var != nullptr && otherVar->getFirstUseOffset() != var->getFirstUseOffset()) {
            continue;
        }
        if (otherVar->getVariableStorage().intersects(newStorage)) {
            if (deleteConflictingVariables) {
                function->removeVariable(otherVar);
            }
            else {
                conflicts.push_back(otherVar);
            }
        }
    }
    if (!conflicts.empty()) {
        generateConflictException(var, newStorage, conflicts, 4);
    }
}

void VariableUtilities::checkVariableConflict(const std::vector<Variable*>& existingVariables, Variable* var, VariableStorage newStorage, VariableConflictHandler* conflictHandler) {
    if (!newStorage.isValid()) {
        return;
    }
    std::vector<Variable*> conflicts;
    for (Variable* otherVar : existingVariables) {
        if (otherVar == nullptr || otherVar == var) {
            continue;
        }
        if (var != nullptr && otherVar->getFirstUseOffset() != var->getFirstUseOffset()) {
            continue;
        }
        if (otherVar->getVariableStorage().intersects(newStorage)) {
            conflicts.push_back(otherVar);
        }
    }
    if (!conflicts.empty()) {
        if (conflictHandler == nullptr || !conflictHandler->resolveConflicts(conflicts)) {
            generateConflictException(var, newStorage, conflicts, 4);
        }
    }
}

void VariableUtilities::appendVariableStorageDetails(Variable* var, VariableStorage storage, std::string& msg) {
    if (var != nullptr) {
        msg += var->getName();
        msg += "{";
        msg += storage.toString();
        msg += "}";
    }
    else {
        msg += storage.toString();
    }
}

void VariableUtilities::generateConflictException(Variable* var, VariableStorage newStorage, const std::vector<Variable*>& conflicts, int maxConflictVarDetails) {
    maxConflictVarDetails = std::min((int)conflicts.size(), maxConflictVarDetails);
    std::string msg = "Variable storage conflict between ";
    appendVariableStorageDetails(var, newStorage, msg);
    msg += " and ";
    for (int i = 0; i < maxConflictVarDetails; i++) {
        if (i != 0) {
            msg += ", ";
        }
        Variable* v = conflicts[i];
        appendVariableStorageDetails(v, v->getVariableStorage(), msg);
    }
    if (maxConflictVarDetails < (int)conflicts.size()) {
        msg += " ... {";
        msg += std::to_string(conflicts.size() - maxConflictVarDetails);
        msg += " more}";
    }
    throw VariableSizeException(msg, true);
}

std::optional<int> VariableUtilities::getBaseStackParamOffset(Function* function) {
    PrototypeModel* convention = function->getCallingConvention();
    if (convention == nullptr) {
        convention = function->getProgram()->getCompilerSpec()->getDefaultCallingConvention();
    }
    if (convention != nullptr) {
        return convention->getStackParameterOffset();
    }
    return std::nullopt;
}

ParameterImpl* VariableUtilities::getThisParameter(Function* function, PrototypeModel* convention) {
    if (convention != nullptr && convention->getName() == "thiscall") {
        DataType* dt = findOrCreateClassStruct(function);
        if (!dt) {
            dt = &VoidDataType::dataType();
        }
        dt = getPointer(function->getProgram(), dt, function->getProgram()->getDefaultPointerSize());
        std::vector<DataType*> arr = { &VoidDataType::dataType(), dt };
        std::vector<VariableStorage> storageLocs = convention->getStorageLocations(function->getProgram(), arr, true);
        VariableStorage thisStorage = storageLocs[1];
        try {
            return new ParameterImpl("this", 0, dt, thisStorage, function->getProgram(), SourceType::ANALYSIS);
        }
        catch (const InvalidInputException& e) {
            Msg::error("VariableUtilities", std::string("Error while generating 'this' parameter for function at ") +
                                             function->getEntryPoint().toString() + ": " + e.what());
        }
    }
    return nullptr;
}

Structure* VariableUtilities::createPlaceholderClassStruct(GhidraClass* classNamespace, DataTypeManager* dataTypeManager) {
    Namespace* classParentNamespace = classNamespace->getParent();
    CategoryPath prefRoot = getPreferredRootNamespaceCategoryPath(dataTypeManager).value_or(CategoryPath::ROOT());
    CategoryPath category = getDataTypeCategoryPath(prefRoot, classParentNamespace);

    DataType* existingDT = dataTypeManager->getDataType(category, classNamespace->getName());
    if (existingDT != nullptr) {
        category = getDataTypeCategoryPath(prefRoot, classNamespace);
        existingDT = dataTypeManager->getDataType(category, classNamespace->getName());
        if (existingDT != nullptr) {
            return nullptr;
        }
    }
    StructureDataType* structDT = new StructureDataType(category, classNamespace->getName(), 0, dataTypeManager);
    structDT->setDescription("PlaceHolder Class Structure");
    return structDT;
}

Structure* VariableUtilities::findOrCreateClassStruct(GhidraClass* classNamespace, DataTypeManager* dataTypeManager) {
    Structure* structDT = findExistingClassStruct(classNamespace, dataTypeManager);
    if (structDT == nullptr) {
        structDT = createPlaceholderClassStruct(classNamespace, dataTypeManager);
    }
    return structDT;
}

Structure* VariableUtilities::findOrCreateClassStruct(Function* function) {
    Namespace* ns = function->getParentNamespace();
    GhidraClass* classNamespace = dynamic_cast<GhidraClass*>(ns);
    if (classNamespace == nullptr) {
        return nullptr;
    }
    return findOrCreateClassStruct(classNamespace, function->getProgram()->getDataTypeManager());
}

Structure* VariableUtilities::findExistingClassStruct(GhidraClass* classNamespace, DataTypeManager* dataTypeManager) {
    Structure* dt = findPreferredDataType<Structure>(dataTypeManager, classNamespace, classNamespace->getName(), true);
    if (dt != nullptr) {
        return dt;
    }
    NamespacePaths namespacePaths = getRelativeCategoryPaths(classNamespace);
    return findDataType<Structure>(dataTypeManager, classNamespace->getName(), [&](const CategoryPath& categoryPath) {
        return getCategoryMatchType(categoryPath, namespacePaths, true);
    });
}

Structure* VariableUtilities::findExistingClassStruct(Function* func) {
    Namespace* ns = func->getParentNamespace();
    GhidraClass* classNamespace = dynamic_cast<GhidraClass*>(ns);
    if (classNamespace == nullptr) {
        return nullptr;
    }
    return findExistingClassStruct(classNamespace, func->getProgram()->getDataTypeManager());
}

bool VariableUtilities::equivalentVariableArrays(const std::vector<Variable*>& vars1, const std::vector<Variable*>& vars2) {
    if (vars1.size() != vars2.size()) {
        return false;
    }
    for (size_t i = 0; i < vars1.size(); i++) {
        if (vars1[i] == nullptr ? vars2[i] != nullptr : !equivalentVariables(vars1[i], vars2[i])) {
            return false;
        }
    }
    return true;
}

bool VariableUtilities::equivalentVariables(Variable* var1, Variable* var2) {
    if (var1 == var2) {
        return true;
    }
    if (var1 == nullptr || var2 == nullptr) {
        return false;
    }
    std::string comment1 = var1->getComment();
    std::string comment2 = var2->getComment();
    return var1->getName() == var2->getName() &&
           var1->getDataType()->isEquivalent(var2->getDataType()) &&
           comment1 == comment2;
}

} // namespace ghidra
