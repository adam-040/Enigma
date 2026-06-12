/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/HiddenReturnAssign.h>
#include <ghidra/Encoder.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/ElementId.h>
#include <ghidra/AttributeId.h>

namespace ghidra {

HiddenReturnAssign::HiddenReturnAssign(ParamListStandard* res, int code)
    : AssignAction(res), retCode(code) {
}

AssignAction* HiddenReturnAssign::clone(ParamListStandard* newResource) {
    return new HiddenReturnAssign(newResource, retCode);
}

bool HiddenReturnAssign::isEquivalent(const AssignAction& op) const {
    const auto* other = dynamic_cast<const HiddenReturnAssign*>(&op);
    if (!other) return false;
    return retCode == other->retCode;
}

int HiddenReturnAssign::assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                                      DataTypeManager* dtManager, int* status, ParameterPieces& res) {
    return retCode;
}

void HiddenReturnAssign::encode(Encoder& encoder) {
    encoder.openElement(ELEM_HIDDEN_RETURN);
    if (retCode == HIDDENRET_PTRPARAM) {
        encoder.writeString(ATTRIB_STRATEGY, STRATEGY_NORMAL);
    } else if (retCode == HIDDENRET_SPECIALREG_VOID) {
        encoder.writeBool(ATTRIB_VOIDLOCK, true);
    }
    encoder.closeElement(ELEM_HIDDEN_RETURN);
}

void HiddenReturnAssign::restoreXml(XmlPullParser& parser) {
    retCode = HIDDENRET_SPECIALREG;
    XmlElement elem = parser.nextElement();
    std::string strategyString = elem.getAttribute(ATTRIB_STRATEGY.name);
    if (!strategyString.empty()) {
        if (strategyString == STRATEGY_NORMAL) {
            retCode = HIDDENRET_PTRPARAM;
        } else if (strategyString == STRATEGY_SPECIAL) {
            retCode = HIDDENRET_SPECIALREG;
        }
    }
    std::string voidLockString = elem.getAttribute(ATTRIB_VOIDLOCK.name);
    if (voidLockString == "true" || voidLockString == "1") {
        retCode = HIDDENRET_SPECIALREG_VOID;
    }
    // Consume end element
    if (parser.hasNext()) parser.nextElement();
}

} // namespace ghidra
