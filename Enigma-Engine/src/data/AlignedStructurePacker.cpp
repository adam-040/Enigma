/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AlignedStructurePacker.h>
#include <ghidra/AlignedComponentPacker.h>
#include <ghidra/StructureInternal.h>
#include <ghidra/InternalDataTypeComponent.h>
#include <ghidra/DataType.h>
#include <ghidra/DataOrganizationImpl.h>

namespace ghidra {

AlignedStructurePacker::AlignedStructurePacker(StructureInternal* structure,
        std::vector<InternalDataTypeComponent*> components)
    : structure_(structure),
      components_(std::move(components)) {}

AlignedStructurePacker::StructurePackResult AlignedStructurePacker::pack() {
    bool componentsChanged = false;
    int componentCount = 0;

    AlignedComponentPacker packer(structure_->getStoredPackingValue(),
                                  structure_->getDataOrganization());

    for (auto* dtc : components_) {
        ++componentCount;
    }

    int index = 0;
    for (auto* dtc : components_) {
        bool isLastComponent = (++index == componentCount);
        packer.addComponent(dtc, isLastComponent);
    }

    int defaultAlignment = packer.getDefaultAlignment();
    int length = packer.getLength();
    componentsChanged |= packer.componentsChanged();

    int alignment = defaultAlignment;
    AlignmentType alignmentType = structure_->getAlignmentType();
    if (alignmentType != AlignmentType::DEFAULT) {
        int minAlign = (alignmentType == AlignmentType::MACHINE)
            ? structure_->getDataOrganization()->getMachineAlignment()
            : structure_->getExplicitMinimumAlignment();
        alignment = std::max(defaultAlignment, minAlign);
    }

    if (length != 0) {
        length = DataOrganizationImpl::getAlignedOffset(alignment, length);
    }

    return StructurePackResult(componentCount, length, alignment, componentsChanged);
}

AlignedStructurePacker::StructurePackResult AlignedStructurePacker::packComponents(
        StructureInternal* structure,
        std::vector<InternalDataTypeComponent*> components) {
    AlignedStructurePacker packer(structure, std::move(components));
    return packer.pack();
}

} // namespace ghidra
