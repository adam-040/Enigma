/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/ParamListStandardOut.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/Pointer.h>
#include <ghidra/DataTypeManager.h>

namespace ghidra {

void ParamListStandardOut::assignMap(const PrototypePieces& proto, DataTypeManager* dtManager,
                                      std::vector<ParameterPieces>& res, bool addAutoParams) {
    std::vector<int> status(getNumGroup(), 0);

    res.emplace_back();
    ParameterPieces& store = res.back();
    if (VoidDataType::isVoidDataType(proto.outtype)) {
        store.type = proto.outtype;
        return;
    }
    int responseCode = assignAddress(proto.outtype, proto, -1, dtManager, status.data(), store);
    if (responseCode == AssignAction::FAIL) {
        responseCode = AssignAction::HIDDENRET_PTRPARAM;
    }
    if (responseCode == AssignAction::HIDDENRET_PTRPARAM ||
        responseCode == AssignAction::HIDDENRET_SPECIALREG ||
        responseCode == AssignAction::HIDDENRET_SPECIALREG_VOID) {
        int sz = (getSpacebase() == nullptr) ? -1 : getSpacebase()->getPointerSize();
        DataType* pointerType = dtManager->getPointer(proto.outtype, sz);
        if (responseCode == AssignAction::HIDDENRET_SPECIALREG_VOID) {
            store.type = &VoidDataType::dataType();
        }
        else {
            store.type = pointerType;
            assignAddress(pointerType, proto, -1, dtManager, status.data(), store);
        }
        store.isIndirect = true;
        if (addAutoParams) {
            ParameterPieces hiddenRet;
            hiddenRet.type = pointerType;
            hiddenRet.hiddenReturnPtr =
                (responseCode == AssignAction::HIDDENRET_SPECIALREG) ||
                (responseCode == AssignAction::HIDDENRET_SPECIALREG_VOID);
            res.push_back(hiddenRet);
        }
    }
}

} // namespace ghidra
