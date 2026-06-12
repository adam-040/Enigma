/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamListStandard.h
/// \brief Standard analysis for parameter lists with model rules and fallback
/// Translated from: ghidra.program.model.lang.ParamListStandard
#pragma once

#include <ghidra/ParamList.h>
#include <ghidra/ParamEntry.h>
#include <ghidra/PrototypePieces.h>
#include <ghidra/ParameterPieces.h>
#include <ghidra/AssignAction.h>
#include <ghidra/ModelRule.h>
#include <vector>

namespace ghidra {

class Language;

class ParamListStandard : public ParamList {
private:
    Language* language_ = nullptr;
    int numgroup_ = 0;
    bool thisbeforeret_ = false;
    bool autoKilledByCall_ = false;
    bool splitMetatype_ = true;
    std::vector<ParamEntry> entry_;
    std::vector<ModelRule*> modelRules_;
    AddressSpace* spacebase_ = nullptr;

    int findEntry(const Address& loc, int size) const;

public:
    ParamListStandard() = default;
    ~ParamListStandard() override;
    ParamList* clone() const override;

    ParamListStandard(const ParamListStandard&) = default;
    ParamListStandard& operator=(const ParamListStandard&) = delete;

    void addEntry(const ParamEntry& pe);
    void addModelRule(ModelRule* rule);
    void setLanguage(Language* lang) { language_ = lang; }
    void setSpacebase(AddressSpace* spc) { spacebase_ = spc; }
    void setNumGroup(int ng) { numgroup_ = ng; }
    void setThisBeforeRet(bool val) { thisbeforeret_ = val; }
    void setAutoKilledByCall(bool val) { autoKilledByCall_ = val; }
    void setSplitMetatype(bool val) { splitMetatype_ = val; }

    int assignAddress(DataType* dt, const PrototypePieces& proto, int pos,
                      DataTypeManager* dtManager, int* status, ParameterPieces& res);
    int assignAddressFallback(StorageClass resource, DataType* tp, bool matchExact,
                              int* status, ParameterPieces& param);

    int getNumGroup() const { return numgroup_; }
    int getNumParamEntry() const { return static_cast<int>(entry_.size()); }
    ParamEntry& getEntry(int index) { return entry_[index]; }
    const ParamEntry& getEntry(int index) const { return entry_[index]; }
    bool isBigEndian() const;

    std::vector<ParamEntry> extractTiles(StorageClass resType) const;
    ParamEntry* extractStack();

    // ParamList interface
    void assignMap(const PrototypePieces& proto, DataTypeManager* dtManage,
                   std::vector<ParameterPieces>& res, bool addAutoParams) override;
    void encode(Encoder* encoder, bool isInput) override;
    void restoreXml(class XmlPullParser* parser, CompilerSpec* cspec) override;
    std::vector<VariableStorage> getPotentialRegisterStorage(Program* prog) override;
    int getStackParameterAlignment() const override;
    int64_t getStackParameterOffset() const override;
    bool possibleParamWithSlot(const Address& loc, int size, WithSlotRec& res) override;
    Language* getLanguage() override;
    AddressSpace* getSpacebase() override;
    bool isThisBeforeRetPointer() const override;
    bool isEquivalent(const ParamList* obj) const override;
};

} // namespace ghidra
