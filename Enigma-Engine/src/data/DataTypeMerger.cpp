#include <ghidra/DataTypeMerger.h>
#include <ghidra/DataTypeMergeException.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/UnionDataType.h>
#include <ghidra/EnumDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/FunctionDefinitionDataType.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/CategoryPath.h>
#include <algorithm>

namespace ghidra {

DataTypeMerger::DataTypeMerger(DataTypeManager* target, DataTypeManager* source,
                               DataTypeConflictHandler* handler)
    : target_(target), source_(source), handler_(handler) {
    if (!target_ || !source_) {
        throw DataTypeMergeException("Target and source DataTypeManagers must not be null");
    }
    if (!handler_) {
        handler_ = &DataTypeConflictHandler::DEFAULT_HANDLER();
    }
}

static bool isCompositeType(DataType* dt) {
    if (!dt) return false;
    return dynamic_cast<StructureDataType*>(dt) ||
           dynamic_cast<UnionDataType*>(dt) ||
           dynamic_cast<EnumDataType*>(dt) ||
           dynamic_cast<PointerDataType*>(dt) ||
           dynamic_cast<ArrayDataType*>(dt) ||
           dynamic_cast<FunctionDefinitionDataType*>(dt) ||
           dynamic_cast<TypedefDataType*>(dt);
}

bool DataTypeMerger::merge() {
    std::vector<DataType*> srcTypes = source_->getDataTypes();

    std::vector<DataType*> primitives;
    std::vector<DataType*> composites;

    for (DataType* dt : srcTypes) {
        if (!dt) continue;
        if (isCompositeType(dt)) {
            composites.push_back(dt);
        } else {
            primitives.push_back(dt);
        }
    }

    for (DataType* dt : primitives) {
        mergeType(dt);
    }

    for (DataType* dt : composites) {
        mergeType(dt);
    }

    return true;
}

DataType* DataTypeMerger::mergeType(DataType* srcType) {
    if (!srcType) return nullptr;

    long srcId = source_->getID(srcType);
    if (srcId >= 0) {
        auto it = idMap_.find(srcId);
        if (it != idMap_.end()) {
            return target_->getDataType(it->second);
        }
    }

    // resolve() checks for existing equivalent types and handles conflicts
    DataType* resolved = target_->resolve(srcType, handler_);
    if (resolved) {
        if (srcId >= 0) {
            long targetId = target_->getID(resolved);
            idMap_[srcId] = targetId;
        }
        mergeCount_++;
        return resolved;
    }

    skipCount_++;
    return nullptr;
}

DataType* DataTypeMerger::cloneForTarget(DataType* srcType) {
    if (!srcType) return nullptr;

    if (auto* srcStruct = dynamic_cast<StructureDataType*>(srcType)) {
        StructureDataType* newStruct = new StructureDataType(
            srcStruct->getCategoryPath(), srcStruct->getName(),
            srcStruct->getLength(), target_);

        for (int i = 0; i < srcStruct->getNumComponents(); i++) {
            DataTypeComponent* comp = srcStruct->getComponent(i);
            if (!comp) continue;

            DataType* compType = comp->getDataType();
            DataType* resolvedCompType = mergeType(compType);
            if (!resolvedCompType) resolvedCompType = compType;

            newStruct->insertAtOffset(comp->getOffset(), resolvedCompType,
                comp->getLength(), comp->getFieldName(),
                comp->getComment());
        }

        return newStruct;
    }

    if (auto* srcUnion = dynamic_cast<UnionDataType*>(srcType)) {
        UnionDataType* newUnion = new UnionDataType(
            srcUnion->getCategoryPath(), srcUnion->getName(), target_);

        for (int i = 0; i < srcUnion->getNumComponents(); i++) {
            DataTypeComponent* comp = srcUnion->getComponent(i);
            if (!comp) continue;

            DataType* compType = comp->getDataType();
            DataType* resolvedCompType = mergeType(compType);
            if (!resolvedCompType) resolvedCompType = compType;

            newUnion->add(resolvedCompType, comp->getFieldName(),
                comp->getComment());
        }

        return newUnion;
    }

    if (auto* srcEnum = dynamic_cast<EnumDataType*>(srcType)) {
        EnumDataType* newEnum = new EnumDataType(
            srcEnum->getCategoryPath(), srcEnum->getName(),
            srcEnum->getLength(), target_);

        std::vector<std::string> names = srcEnum->getNames();
        for (const auto& name : names) {
            long long value = srcEnum->getValue(name);
            std::string comment = srcEnum->getComment(name);
            newEnum->add(name, value, comment);
        }

        return newEnum;
    }

    if (auto* srcPtr = dynamic_cast<PointerDataType*>(srcType)) {
        DataType* baseType = srcPtr->getDataType();
        DataType* resolvedBase = mergeType(baseType);
        if (!resolvedBase) resolvedBase = baseType;

        return new PointerDataType(resolvedBase, target_);
    }

    if (auto* srcArr = dynamic_cast<ArrayDataType*>(srcType)) {
        DataType* elemType = srcArr->getDataType();
        DataType* resolvedElem = mergeType(elemType);
        if (!resolvedElem) resolvedElem = elemType;

        return new ArrayDataType(resolvedElem, srcArr->getNumElements(),
            srcArr->getElementLength(), target_);
    }

    if (auto* srcTypedef = dynamic_cast<TypedefDataType*>(srcType)) {
        DataType* baseType = srcTypedef->getDataType();
        DataType* resolvedBase = mergeType(baseType);
        if (!resolvedBase) resolvedBase = baseType;

        return new TypedefDataType(srcTypedef->getCategoryPath(),
            srcTypedef->getName(), resolvedBase, target_);
    }

    if (auto* srcFunc = dynamic_cast<FunctionDefinitionDataType*>(srcType)) {
        FunctionDefinitionDataType* newFunc = new FunctionDefinitionDataType(
            srcFunc->getName(), target_);

        DataType* retType = srcFunc->getReturnType();
        if (retType) {
            DataType* resolvedRet = mergeType(retType);
            if (resolvedRet) newFunc->setReturnType(resolvedRet);
        }

        std::vector<ParameterDefinition*> srcArgs = srcFunc->getArguments();
        std::vector<ParameterDefinition*> newArgs;
        for (ParameterDefinition* param : srcArgs) {
            if (!param) continue;

            DataType* paramType = param->getDataType();
            DataType* resolvedParam = mergeType(paramType);
            if (!resolvedParam) resolvedParam = paramType;

            ParameterDefinition* newParam = new ParameterDefinitionImpl(
                param->getName(), resolvedParam, param->getComment());
            newArgs.push_back(newParam);
        }
        newFunc->setArguments(newArgs);

        return newFunc;
    }

    return srcType->clone(target_);
}

bool DataTypeMerger::isEquivalent(DataType* a, DataType* b) {
    if (!a || !b) return false;
    return a->isEquivalent(b);
}

} // namespace ghidra
