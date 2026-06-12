/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeComparator.cpp
#include "ghidra/DataTypeComparator.h"
#include "ghidra/DataType.h"
#include "ghidra/DataTypeManager.h"
#include "ghidra/CategoryPath.h"
#include "ghidra/DataTypeNameComparator.h"

namespace ghidra {

const DataTypeComparator DataTypeComparator::INSTANCE;

int DataTypeComparator::compare(const DataType* a, const DataType* b) const {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;

    int nameCmp = DataTypeNameComparator::INSTANCE.compare(a->getName(), b->getName());
    if (nameCmp != 0) return nameCmp;

    DataTypeManager* dtmA = a->getDataTypeManager();
    DataTypeManager* dtmB = b->getDataTypeManager();
    if (dtmA == nullptr && dtmB == nullptr) return 0;
    if (dtmA == nullptr) return -1;
    if (dtmB == nullptr) return 1;

    int dtmCmp = dtmA->getName().compare(dtmB->getName());
    if (dtmCmp != 0) return dtmCmp;

    return a->getCategoryPath().getPath().compare(b->getCategoryPath().getPath());
}

} // namespace ghidra
