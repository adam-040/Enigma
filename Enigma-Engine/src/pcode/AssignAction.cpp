/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/AssignAction.h>
#include <ghidra/HiddenReturnAssign.h>
#include <ghidra/GotoStack.h>
#include <ghidra/ConsumeAs.h>
#include <ghidra/ExtraStack.h>
#include <ghidra/ConsumeExtra.h>
#include <ghidra/ConsumeRemaining.h>
#include <ghidra/ParamListStandard.h>
#include <ghidra/MultiMemberAssign.h>
#include <ghidra/MultiSlotAssign.h>
#include <ghidra/MultiSlotDualAssign.h>
#include <ghidra/ElementId.h>
#include <ghidra/XmlPullParser.h>
#include <stdexcept>

namespace ghidra {

AssignAction* AssignAction::restoreActionXml(XmlPullParser& parser, ParamListStandard* res) {
    if (!parser.hasNext()) return nullptr;
    XmlElement elem = parser.peek();
    const std::string& name = elem.getName();

    AssignAction* action = nullptr;
    if (name == ELEM_GOTO_STACK.name) {
        action = new GotoStack(res, 0);
    } else if (name == ELEM_JOIN.name) {
        action = new MultiSlotAssign(res);
    } else if (name == ELEM_CONSUME.name) {
        action = new ConsumeAs(StorageClass::GENERAL, res);
    } else if (name == ELEM_HIDDEN_RETURN.name) {
        action = new HiddenReturnAssign(res, HIDDENRET_SPECIALREG);
    } else if (name == ELEM_JOIN_PER_PRIMITIVE.name) {
        action = new MultiMemberAssign(StorageClass::GENERAL, false, res->isBigEndian(), res);
    } else if (name == ELEM_JOIN_DUAL_CLASS.name) {
        action = new MultiSlotDualAssign(res);
    } else if (name == ELEM_CONVERT_TO_PTR.name) {
        throw std::runtime_error("ConvertToPointer not yet ported");
    } else {
        throw std::runtime_error("Unknown model rule action: " + name);
    }
    action->restoreXml(parser);
    return action;
}

AssignAction* AssignAction::restoreSideeffectXml(XmlPullParser& parser, ParamListStandard* res) {
    if (!parser.hasNext()) return nullptr;
    XmlElement elem = parser.peek();
    const std::string& name = elem.getName();

    AssignAction* action = nullptr;
    if (name == ELEM_CONSUME_EXTRA.name) {
        action = new ConsumeExtra(res);
    } else if (name == ELEM_EXTRA_STACK.name) {
        action = new ExtraStack(res, 0);
    } else if (name == ELEM_CONSUME_REMAINING.name) {
        action = new ConsumeRemaining(res);
    } else {
        throw std::runtime_error("Unknown model rule sideeffect: " + name);
    }
    action->restoreXml(parser);
    return action;
}

AssignAction* AssignAction::restorePreconditionXml(XmlPullParser& parser, ParamListStandard* res) {
    if (!parser.hasNext()) return nullptr;
    XmlElement elem = parser.peek();
    const std::string& name = elem.getName();

    if (name == ELEM_CONSUME_EXTRA.name) {
        ConsumeExtra* action = new ConsumeExtra(res);
        action->restoreXml(parser);
        return action;
    }
    return nullptr;
}

void AssignAction::justifyPieces(std::vector<class Varnode*>& pieces, int offset,
                                  bool isBigEndian, bool consumeMostSig, bool justifyRight) {
    bool addOffset = isBigEndian ^ consumeMostSig ^ justifyRight;
    int pos = justifyRight ? 0 : static_cast<int>(pieces.size()) - 1;

    Varnode* vn = pieces[pos];
    // Stub: actual piece adjustment omitted
}

} // namespace ghidra
