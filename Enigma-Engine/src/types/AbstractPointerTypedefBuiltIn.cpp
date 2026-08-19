/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AbstractPointerTypedefBuiltIn.h>
#include <ghidra/Pointer.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/Settings.h>

namespace ghidra {

static std::string tempNameIfNeeded(const std::string& baseName) {
    return baseName.empty() ? "TEMP" : baseName;
}

AbstractPointerTypedefBuiltIn::AbstractPointerTypedefBuiltIn(const std::string& name,
        DataType* referencedDataType, int pointerSize, DataTypeManager* dtm)
    : BuiltIn(referencedDataType ? referencedDataType->getCategoryPath() : CategoryPath::ROOT(),
              tempNameIfNeeded(name), dtm) {
    setTypedefName(name);
    modelTypedef_ = new TypedefDataType(CategoryPath::ROOT(), "TEMP",
        new PointerDataType(referencedDataType, pointerSize, dtm), dtm, true);
}

AbstractPointerTypedefBuiltIn::AbstractPointerTypedefBuiltIn(const std::string& name,
        Pointer* pointerDataType, DataTypeManager* dtm)
    : BuiltIn(pointerDataType->getCategoryPath(), tempNameIfNeeded(name), dtm) {
    setTypedefName(name);
    modelTypedef_ = new TypedefDataType(CategoryPath::ROOT(), "TEMP",
        pointerDataType->clone(dtm), dtm, true);
}

AbstractPointerTypedefBuiltIn::~AbstractPointerTypedefBuiltIn() {
    delete modelTypedef_;
}

void AbstractPointerTypedefBuiltIn::enableAutoNaming() {
    typedefName_.clear();
}

bool AbstractPointerTypedefBuiltIn::isAutoNamed() const {
    return typedefName_.empty();
}

DataType* AbstractPointerTypedefBuiltIn::getReferencedDataType() {
    auto* ptr = dynamic_cast<Pointer*>(getDataType());
    return ptr ? ptr->getDataType() : nullptr;
}

void AbstractPointerTypedefBuiltIn::setTypedefName(const std::string& name) {
    typedefName_ = name;
}

bool AbstractPointerTypedefBuiltIn::isEquivalent(const DataType* obj) const {
    if (obj == this) return true;
    auto* td = dynamic_cast<const TypeDef*>(obj);
    if (!td) return false;
    if (getName() != td->getName()) return false;
    return getDataType()->isEquivalent(td->getDataType());
}

std::string AbstractPointerTypedefBuiltIn::getName() const {
    if (typedefName_.empty()) {
        return TypedefDataType(*modelTypedef_).getName();
    }
    return typedefName_;
}

bool AbstractPointerTypedefBuiltIn::hasLanguageDependantLength() const {
    return modelTypedef_->hasLanguageDependantLength();
}

int AbstractPointerTypedefBuiltIn::getLength() const {
    return modelTypedef_->getLength();
}

int AbstractPointerTypedefBuiltIn::getAlignedLength() const {
    return modelTypedef_->getAlignedLength();
}

DataType* AbstractPointerTypedefBuiltIn::getDataType() const {
    return modelTypedef_->getDataType();
}

DataType* AbstractPointerTypedefBuiltIn::getBaseDataType() const {
    return modelTypedef_->getBaseDataType();
}

bool AbstractPointerTypedefBuiltIn::dependsOn(const DataType* dt) const {
    DataType* myDt = getDataType();
    return (myDt == dt || myDt->dependsOn(dt));
}

std::string AbstractPointerTypedefBuiltIn::getDescription() const {
    return "AbstractPointerTypedefBuiltIn: " + getName();
}

std::string AbstractPointerTypedefBuiltIn::toString() const {
    return "AbstractPointerTypedefBuiltIn: typedef " + getName() + " " + getDataType()->getName();
}

DataType* AbstractPointerTypedefBuiltIn::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<AbstractPointerTypedefBuiltIn*>(this);
    }
    return new AbstractPointerTypedefBuiltIn(typedefName_, dynamic_cast<Pointer*>(getDataType()), dtm);
}

std::vector<SettingsDefinition*> AbstractPointerTypedefBuiltIn::getSettingsDefinitions() const {
    return modelTypedef_->getSettingsDefinitions();
}

std::string AbstractPointerTypedefBuiltIn::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    if (!settings) settings = getDefaultSettings();
    return modelTypedef_->getRepresentation(buf, settings, length);
}

} // namespace ghidra
