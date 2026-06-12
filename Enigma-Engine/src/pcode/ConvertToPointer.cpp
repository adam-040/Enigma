/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ConvertToPointer.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/Pointer.h>

namespace ghidra {

ConvertToPointer::ConvertToPointer(ParamListStandard* res, AddressSpace* spc)
    : AssignAction(res), space(spc) {
    if (space == nullptr && res != nullptr) {
        // space = res->getSpacebase();  // Requires ParamListStandard
    }
}

AssignAction* ConvertToPointer::clone(ParamListStandard* newResource) {
    return new ConvertToPointer(newResource, space);
}

bool ConvertToPointer::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const ConvertToPointer*>(&op);
    if (!other) return false;
    if (space == nullptr && other->space == nullptr) return true;
    if (space == nullptr || other->space == nullptr) return false;
    return *space == *other->space;
}

int ConvertToPointer::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                     DataTypeManager* dtManager, int* status,
                                     ParameterPieces& res) {
    if (dtManager == nullptr)
        return FAIL;
    int pointersize = (space != nullptr) ? space->getPointerSize() : -1;
    DataType* pointertp = dtManager->getPointer(dt, pointersize);
    if (pointertp == nullptr)
        return FAIL;
    res.isIndirect = true;
    return SUCCESS;
}

void ConvertToPointer::encode(Encoder& encoder) {
    // Stub
}

void ConvertToPointer::restoreXml(class XmlPullParser& parser) {
    // Stub
}

} // namespace ghidra
