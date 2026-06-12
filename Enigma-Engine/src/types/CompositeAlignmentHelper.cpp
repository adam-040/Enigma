/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CompositeAlignmentHelper.cpp
/// \brief Alignment helper for composite data types
#include "ghidra/CompositeAlignmentHelper.h"

namespace ghidra {

int CompositeAlignmentHelper::getPackedAlignment(int componentAlignment, int packingValue) {
    int alignment = componentAlignment;
    if (packingValue > 0 && packingValue < componentAlignment) {
        alignment = packingValue;
    }
    return alignment;
}

int CompositeAlignmentHelper::getAlignment(DataOrganization* dataOrganization, CompositeInternal* composite) {
    int minimumAlignment = composite->getStoredMinimumAlignment();
    if (minimumAlignment < CompositeInternal::DEFAULT_ALIGNMENT) {
        minimumAlignment = dataOrganization->getMachineAlignment();
    }
    return (minimumAlignment == CompositeInternal::DEFAULT_ALIGNMENT) ? 1 : minimumAlignment;
}

} // namespace ghidra
