/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CompositeAlignmentHelper.h
/// \brief Alignment helper for composite data types.
#pragma once

#include "CompositeInternal.h"
#include "DataOrganizationImpl.h"

namespace ghidra {

class DataTypeComponent;

class CompositeAlignmentHelper {
public:
    static int getPackedAlignment(int componentAlignment, int packingValue);

    static int getAlignment(DataOrganization* dataOrganization, CompositeInternal* composite);
};

} // namespace ghidra
