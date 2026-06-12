/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/PointerTypedefBuilder.h>
#include <ghidra/Pointer.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/PointerTypeSettingsDefinition.h>
#include <ghidra/OffsetShiftSettingsDefinition.h>
#include <ghidra/OffsetMaskSettingsDefinition.h>
#include <ghidra/ComponentOffsetSettingsDefinition.h>
#include <ghidra/AddressSpaceSettingsDefinition.h>
#include <ghidra/Settings.h>

namespace ghidra {

PointerTypedefBuilder::PointerTypedefBuilder(DataType* baseDataType, int pointerSize, DataTypeManager* dtm) {
    typedef_ = new PointerTypedef("", baseDataType, pointerSize, dtm);
}

PointerTypedefBuilder::PointerTypedefBuilder(Pointer* pointerDataType, DataTypeManager* dtm) {
    typedef_ = new PointerTypedef("", pointerDataType, dtm);
}

PointerTypedefBuilder& PointerTypedefBuilder::name(const std::string& name) {
    typedef_->setName(name);
    return *this;
}

PointerTypedefBuilder& PointerTypedefBuilder::type(PointerType type) {
    PointerTypeSettingsDefinition::def().setType(typedef_->getDefaultSettings(), type);
    return *this;
}

PointerTypedefBuilder& PointerTypedefBuilder::bitShift(int shift) {
    OffsetShiftSettingsDefinition::def().setValue(typedef_->getDefaultSettings(), shift);
    return *this;
}

PointerTypedefBuilder& PointerTypedefBuilder::bitMask(uint64_t unsignedMask) {
    OffsetMaskSettingsDefinition::def().setValue(typedef_->getDefaultSettings(),
                                                  static_cast<int64_t>(unsignedMask));
    return *this;
}

PointerTypedefBuilder& PointerTypedefBuilder::componentOffset(int64_t offset) {
    ComponentOffsetSettingsDefinition::def().setValue(typedef_->getDefaultSettings(), offset);
    return *this;
}

PointerTypedefBuilder& PointerTypedefBuilder::addressSpace(AddressSpace* space) {
    AddressSpaceSettingsDefinition::def().setValue(typedef_->getDefaultSettings(),
        space ? space->getName() : "");
    return *this;
}

PointerTypedefBuilder& PointerTypedefBuilder::addressSpace(const std::string& spaceName) {
    AddressSpaceSettingsDefinition::def().setValue(typedef_->getDefaultSettings(), spaceName);
    return *this;
}

TypeDef* PointerTypedefBuilder::build() {
    return typedef_;
}

} // namespace ghidra
