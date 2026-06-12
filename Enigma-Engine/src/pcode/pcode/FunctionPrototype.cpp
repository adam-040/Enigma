/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionPrototype.cpp
/// \brief FunctionPrototype skeleton implementation.
#include "ghidra/pcode/FunctionPrototype.h"
#include "ghidra/pcode/HighFunction.h"
#include "ghidra/LocalSymbolMap.h"
#include "ghidra/ParameterDefinition.h"
#include "ghidra/FunctionSignature.h"
#include "ghidra/CompilerSpec.h"
#include "ghidra/Decoder.h"
#include "ghidra/Encoder.h"
#include "ghidra/ElementId.h"

namespace {
struct SimpleParamDef : public ghidra::ParameterDefinition {
    std::string name_;
    std::string type_;
    SimpleParamDef(const std::string& n, const std::string& t) : name_(n), type_(t) {}
    int getOrdinal() const override { return 0; }
    ghidra::DataType* getDataType() const override { return nullptr; }
    void setDataType(ghidra::DataType*) override {}
    std::string getName() const override { return name_; }
    int getLength() const override { return 1; }
    void setName(const std::string& n) override { name_ = n; }
    std::string getComment() const override { return {}; }
    void setComment(const std::string&) override {}
    bool isEquivalent(const ghidra::ParameterDefinition* p) const override {
        return p && p->getName() == name_;
    }
};
} // anonymous namespace

namespace ghidra {
namespace pcode {

FunctionPrototype::FunctionPrototype()
    : highFunction(nullptr), localsyms(nullptr),
      returntype(nullptr), returnstorage(nullptr) {}

FunctionPrototype::FunctionPrototype(HighFunction* hf)
    : highFunction(hf), localsyms(hf ? hf->getLocalSymbolMap() : nullptr),
      returntype(nullptr), returnstorage(nullptr) {}

FunctionPrototype::FunctionPrototype(LocalSymbolMap* ls, void* func)
    : highFunction(nullptr), localsyms(ls),
      returntype(nullptr), returnstorage(nullptr) {
    (void)func;
}

FunctionPrototype::FunctionPrototype(FunctionSignature* proto, CompilerSpec* cspec,
                                     bool voidimpliesdotdotdot)
    : highFunction(nullptr), localsyms(nullptr),
      returntype(nullptr), returnstorage(nullptr) {
    (void)proto; (void)cspec; (void)voidimpliesdotdotdot;
}

int FunctionPrototype::getNumParams() const {
    if (localsyms != nullptr) {
        return static_cast<int>(localsyms->size());
    }
    return static_cast<int>(params.size());
}

void FunctionPrototype::addParam(const std::string& nm, const std::string& ty) {
    params.push_back(new SimpleParamDef(nm, ty));
    paramNames_.push_back(nm);
    paramTypes_.push_back(ty);
}

void FunctionPrototype::decode(Decoder& decoder, EquateTable* equateTable) {
    (void)equateTable;
    for (;;) {
        int id = decoder.getNextAttributeId();
        if (id == 0) break;
        if (id == 0) break;
    }
}

void FunctionPrototype::encode(Encoder& encoder) const {
    (void)encoder;
}

}  // namespace pcode
}  // namespace ghidra
