/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/ParamListImpl.h"
#include "ghidra/PrototypePieces.h"
#include "ghidra/ParameterPieces.h"
#include "ghidra/Program.h"

namespace ghidra {

ParamListImpl::ParamListImpl(Language* lang, AddressSpace* spacebase,
                              int stackAlign, int64_t stackOffset,
                              bool thisBeforeRet)
    : language_(lang), spacebase_(spacebase),
      stackAlignment_(stackAlign), stackOffset_(stackOffset),
      thisBeforeRet_(thisBeforeRet) {}

void ParamListImpl::assignMap(const PrototypePieces& proto, DataTypeManager* dtManage,
                               std::vector<ParameterPieces>& res, bool addAutoParams) {
    res.clear();
    if (proto.outtype) {
        ParameterPieces out;
        out.type = proto.outtype;
        res.push_back(out);
    }
    for (size_t i = 0; i < proto.intypes.size(); ++i) {
        ParameterPieces in;
        in.type = proto.intypes[i];
        res.push_back(in);
    }
}

void ParamListImpl::encode(Encoder* encoder, bool isInput) {
}

void ParamListImpl::restoreXml(XmlPullParser* parser, CompilerSpec* cspec) {
}

std::vector<VariableStorage> ParamListImpl::getPotentialRegisterStorage(Program* prog) {
    return {};
}

int ParamListImpl::getStackParameterAlignment() const {
    return stackAlignment_;
}

int64_t ParamListImpl::getStackParameterOffset() const {
    return stackOffset_;
}

bool ParamListImpl::possibleParamWithSlot(const Address& loc, int size, WithSlotRec& res) {
    return false;
}

Language* ParamListImpl::getLanguage() {
    return language_;
}

AddressSpace* ParamListImpl::getSpacebase() {
    return spacebase_;
}

bool ParamListImpl::isThisBeforeRetPointer() const {
    return thisBeforeRet_;
}

bool ParamListImpl::isEquivalent(const ParamList* obj) const {
    auto* other = dynamic_cast<const ParamListImpl*>(obj);
    if (!other) return false;
    return stackAlignment_ == other->stackAlignment_ &&
           stackOffset_ == other->stackOffset_ &&
           thisBeforeRet_ == other->thisBeforeRet_ &&
           spacebase_ == other->spacebase_;
}

} // namespace ghidra
