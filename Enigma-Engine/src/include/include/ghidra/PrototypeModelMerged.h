/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PrototypeModelMerged.h
/// \brief A PrototypeModel that selects between multiple underlying models
///        based on the best fit for an actual call signature.
/// Translated from: ghidra.program.model.lang.PrototypeModelMerged
#pragma once

#include "ghidra/PrototypeModel.h"
#include "ghidra/ParamList.h"
#include <vector>

namespace ghidra {

class Address;
class Parameter;
class PcodeInjectLibrary;
class XmlPullParser;

class PrototypeModelMerged : public PrototypeModel {
public:
    PrototypeModelMerged();

    bool isMerged() const override { return true; }
    int numModels() const { return (int)modellist.size(); }
    PrototypeModel* getModel(int i) const { return modellist[i]; }

    void encode(Encoder& encoder, PcodeInjectLibrary* injectLibrary);
    void restoreXml(XmlPullParser* parser, const std::vector<PrototypeModel*>& modelList);

    PrototypeModel* selectModel(const std::vector<Parameter*>& params);

    bool isEquivalent(const PrototypeModel& obj) const;

private:
    std::vector<PrototypeModel*> modellist;
};

} // namespace ghidra
