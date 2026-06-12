/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ParamList.h
/// \brief A group of ParamEntry that form a complete set for passing parameters
/// Translated from: ghidra.program.model.lang.ParamList
#pragma once

#include <vector>
#include <cstdint>
#include "ghidra/Address.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/DataTypeManager.h"
#include "ghidra/VariableStorage.h"
#include "ghidra/Encoder.h"

namespace ghidra {

class PrototypePieces;
class ParameterPieces;
class CompilerSpec;
class Program;
class Language;

class ParamList {
public:
    struct WithSlotRec {
        int slot = 0;
        int slotsize = 0;
    };

    virtual ~ParamList() = default;
    virtual ParamList* clone() const = 0;
    virtual void assignMap(const PrototypePieces& proto, DataTypeManager* dtManage,
                           std::vector<ParameterPieces>& res, bool addAutoParams) = 0;
    virtual void encode(Encoder* encoder, bool isInput) = 0;
    virtual void restoreXml(class XmlPullParser* parser, CompilerSpec* cspec) = 0;
    virtual std::vector<VariableStorage> getPotentialRegisterStorage(Program* prog) = 0;
    virtual int getStackParameterAlignment() const = 0;
    virtual int64_t getStackParameterOffset() const = 0;
    virtual bool possibleParamWithSlot(const Address& loc, int size, WithSlotRec& res) = 0;
    virtual Language* getLanguage() = 0;
    virtual AddressSpace* getSpacebase() = 0;
    virtual bool isThisBeforeRetPointer() const = 0;
    virtual bool isEquivalent(const ParamList* obj) const = 0;
};

} // namespace ghidra
