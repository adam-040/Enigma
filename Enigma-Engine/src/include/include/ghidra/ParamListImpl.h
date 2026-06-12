/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamListImpl.h
/// \brief Concrete implementation of ParamList for standard parameter passing conventions
/// Translated from: ghidra.program.model.lang.ParamListStandard
#pragma once

#include <ghidra/ParamList.h>
#include <ghidra/Language.h>
#include <ghidra/AddressSpace.h>

namespace ghidra {

class ParamListImpl : public ParamList {
public:
    ParamListImpl(Language* lang, AddressSpace* spacebase = nullptr,
                  int stackAlign = 4, int64_t stackOffset = 0,
                  bool thisBeforeRet = false);

    ParamList* clone() const override { return new ParamListImpl(*this); }
    void assignMap(const PrototypePieces& proto, DataTypeManager* dtManage,
                   std::vector<ParameterPieces>& res, bool addAutoParams) override;
    void encode(Encoder* encoder, bool isInput) override;
    void restoreXml(XmlPullParser* parser, CompilerSpec* cspec) override;
    std::vector<VariableStorage> getPotentialRegisterStorage(Program* prog) override;
    int getStackParameterAlignment() const override;
    int64_t getStackParameterOffset() const override;
    bool possibleParamWithSlot(const Address& loc, int size, WithSlotRec& res) override;
    Language* getLanguage() override;
    AddressSpace* getSpacebase() override;
    bool isThisBeforeRetPointer() const override;
    bool isEquivalent(const ParamList* obj) const override;

private:
    Language* language_;
    AddressSpace* spacebase_;
    int stackAlignment_;
    int64_t stackOffset_;
    bool thisBeforeRet_;
};

} // namespace ghidra
