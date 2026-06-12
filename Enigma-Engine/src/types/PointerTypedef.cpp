/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/PointerTypedef.h>
#include <ghidra/Pointer.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/DataOrganization.h>
#include <ghidra/TypedefDataType.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/Settings.h>
#include <ghidra/SettingsImpl.h>
#include <typeinfo>

namespace ghidra {

static std::string tempNameIfNeeded(const std::string& baseName) {
    return baseName.empty() ? "TEMP" : baseName;
}

void PointerTypedef::init(const std::string& typeDefName, DataType* baseType) {
    isAutoNamed_ = typeDefName.empty();
    modelTypedef_ = new TypedefDataType("TEMP", baseType);
}

PointerTypedef::PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
        int pointerSize, DataTypeManager* dtm, AddressSpace* space)
    : GenericDataType(referencedDataType ? referencedDataType->getCategoryPath() : CategoryPath::ROOT(),
                      tempNameIfNeeded(typeDefName), dtm) {
    init(typeDefName, new PointerDataType(referencedDataType,
         getPreferredPointerSize(pointerSize, dtm, space), dtm));
    AddressSpaceSettingsDefinition::def().setValue(getDefaultSettings(), space->getName());
}

PointerTypedef::PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
        int pointerSize, DataTypeManager* dtm, PointerType type)
    : GenericDataType(referencedDataType ? referencedDataType->getCategoryPath() : CategoryPath::ROOT(),
                      tempNameIfNeeded(typeDefName), dtm) {
    init(typeDefName, new PointerDataType(referencedDataType, pointerSize, dtm));
    PointerTypeSettingsDefinition::def().setType(getDefaultSettings(), type);
}

PointerTypedef::PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
        int pointerSize, DataTypeManager* dtm, long componentOffset)
    : GenericDataType(referencedDataType ? referencedDataType->getCategoryPath() : CategoryPath::ROOT(),
                      tempNameIfNeeded(typeDefName), dtm) {
    init(typeDefName, new PointerDataType(referencedDataType, pointerSize, dtm));
    ComponentOffsetSettingsDefinition::def().setValue(getDefaultSettings(), componentOffset);
}

PointerTypedef::PointerTypedef(const std::string& typeDefName, DataType* referencedDataType,
        int pointerSize, DataTypeManager* dtm)
    : GenericDataType(referencedDataType ? referencedDataType->getCategoryPath() : CategoryPath::ROOT(),
                      tempNameIfNeeded(typeDefName), dtm) {
    init(typeDefName, new PointerDataType(referencedDataType, pointerSize, dtm));
}

PointerTypedef::PointerTypedef(const std::string& typeDefName, Pointer* pointerDataType,
        DataTypeManager* dtm)
    : GenericDataType(pointerDataType->getCategoryPath(), tempNameIfNeeded(typeDefName), dtm) {
    init(typeDefName, pointerDataType->clone(dtm));
}

PointerTypedef::~PointerTypedef() {
    delete modelTypedef_;
}

void PointerTypedef::enableAutoNaming() {
    isAutoNamed_ = true;
}

bool PointerTypedef::isAutoNamed() const {
    return isAutoNamed_;
}

DataType* PointerTypedef::getReferencedDataType() {
    auto* ptr = dynamic_cast<Pointer*>(getDataType());
    return ptr ? ptr->getDataType() : nullptr;
}

bool PointerTypedef::isEquivalent(const DataType* obj) const {
    if (obj == this) return true;
    auto* td = dynamic_cast<const TypeDef*>(obj);
    if (!td) return false;
    if (getName() != td->getName()) return false;
    return getDataType()->isEquivalent(td->getDataType());
}

std::string PointerTypedef::getDescription() const {
    return "Pointer-Typedef";
}

void PointerTypedef::setName(const std::string& name) {
    GenericDataType::setName(name);
    isAutoNamed_ = false;
}

std::string PointerTypedef::getName() const {
    if (isAutoNamed_) {
        return TypedefDataType(*modelTypedef_).getName();
    }
    return GenericDataType::getName();
}

bool PointerTypedef::hasLanguageDependantLength() const {
    return modelTypedef_->hasLanguageDependantLength();
}

int PointerTypedef::getLength() const {
    return modelTypedef_->getLength();
}

int PointerTypedef::getAlignedLength() const {
    return modelTypedef_->getAlignedLength();
}

DataType* PointerTypedef::getDataType() const {
    return modelTypedef_->getDataType();
}

DataType* PointerTypedef::getBaseDataType() const {
    return modelTypedef_->getBaseDataType();
}

std::vector<SettingsDefinition*> PointerTypedef::getSettingsDefinitions() const {
    return modelTypedef_->getSettingsDefinitions();
}

std::vector<TypeDefSettingsDefinition*> PointerTypedef::getTypeDefSettingsDefinitions() const {
    return modelTypedef_->getTypeDefSettingsDefinitions();
}

Settings* PointerTypedef::getDefaultSettings() const {
    if (!defaultSettings_) {
        const_cast<PointerTypedef*>(this)->defaultSettings_ = new SettingsImpl();
    }
    return defaultSettings_;
}

bool PointerTypedef::dependsOn(const DataType* dt) const {
    DataType* myDt = getDataType();
    return (myDt == dt || myDt->dependsOn(dt));
}

std::string PointerTypedef::toString() const {
    if (isAutoNamed_) {
        return "PointerTypedef: " + getName();
    }
    return "PointerTypedef: typedef " + getName() + " " + getDataType()->getName();
}

const std::type_info& PointerTypedef::getValueClass(Settings* settings) const {
    return modelTypedef_->getValueClass(settings);
}

std::string PointerTypedef::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return modelTypedef_->getRepresentation(buf, settings, length);
}

PointerTypedef* PointerTypedef::clone(DataTypeManager* dtm) const {
    if (dataMgr_ == dtm) {
        return const_cast<PointerTypedef*>(this);
    }
    return copy(dtm);
}

PointerTypedef* PointerTypedef::copy(DataTypeManager* dtm) const {
    auto* ptrType = dynamic_cast<Pointer*>(getDataType());
    std::string n = isAutoNamed_ ? "" : getName();
    auto* td = new PointerTypedef(n, ptrType, getDataTypeManager());
    return td;
}

int PointerTypedef::getPreferredPointerSize(int pointerSize, DataTypeManager* dtm, AddressSpace* space) {
    if (pointerSize > 0) return pointerSize;
    pointerSize = space->getSize() / 8;
    if (dtm && dtm->getDataOrganization() && dtm->getDataOrganization()->getPointerSize() == pointerSize) {
        pointerSize = -1;
    }
    return pointerSize;
}

} // namespace ghidra
