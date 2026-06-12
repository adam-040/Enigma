/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionPrototype.h
/// \brief High-level prototype of a function based on Varnodes.
/// Translated from: ghidra.program.model.pcode.FunctionPrototype
#pragma once

#include <ghidra/Address.h>
#include <ghidra/EquateTable.h>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class DataType;
class TypeDef;
class ParameterDefinition;
class LocalSymbolMap;
class FunctionSignature;
class CompilerSpec;
class Decoder;
class Encoder;

namespace pcode {

class HighFunction;

/**
 * High-level function prototype (return type, parameters, model name,
 * calling-convention flags, stack extra-pop, etc.).
 *
 * Two backing modes:
 *  - LocalSymbolMap: the prototype is reconstructed from the symbol map
 *    owned by the decompiler's HighFunction (used for full decompiles).
 *  - ParameterDefinition[]: an internally backed prototype (used when
 *    only a FunctionSignature is available, e.g. for static analysis).
 */
class FunctionPrototype {
public:
    static constexpr int UNKNOWN_EXTRAPOP = -1;

    FunctionPrototype();
    explicit FunctionPrototype(HighFunction* hf);
    FunctionPrototype(LocalSymbolMap* ls, void* func);
    FunctionPrototype(FunctionSignature* proto, CompilerSpec* cspec,
                      bool voidimpliesdotdotdot);

    // Accessors
    HighFunction* getHighFunction() const { return highFunction; }
    LocalSymbolMap* getLocalSymbolMap() const { return localsyms; }
    const std::string& getModelName() const { return modelname; }
    const std::string& getInjectName() const { return injectname; }
    const std::string& getName() const { return name; }
    void setName(const std::string& n) { name = n; }
    DataType* getReturnType() const { return returntype; }
    void setReturnType(DataType* t) { returntype = t; }
    void* getReturnStorage() const { return returnstorage; }
    void setReturnStorage(void* s) { returnstorage = s; }

    bool isModelLock() const { return modellock; }
    void setModelLock(bool m) { modellock = m; }
    bool isVoidInputLock() const { return voidinputlock; }
    void setVoidInputLock(bool v) { voidinputlock = v; }
    bool isOutputLock() const { return outputlock; }
    void setOutputLock(bool o) { outputlock = o; }

    bool isVarArg() const { return dotdotdot; }
    void setVarArg(bool v) { dotdotdot = v; }
    bool isInline() const { return isinline; }
    void setInline(bool i) { isinline = i; }
    bool isNoReturn() const { return noreturn; }
    void setNoReturn(bool n) { noreturn = n; }
    bool hasCustomStorage() const { return custom; }
    void setCustomStorage(bool c) { custom = c; }
    bool hasThisPointer() const { return hasThisPtr; }
    void setThisPointer(bool t) { hasThisPtr = t; }
    bool isConstruct() const { return construct; }
    void setConstruct(bool c) { construct = c; }
    bool isDestruct() const { return destruct; }
    void setDestruct(bool d) { destruct = d; }

    int getExtrapop() const { return extrapop; }
    void setExtrapop(int e) { extrapop = e; }

    int getNumParams() const;
    const std::string& getParamName(int i) const { return paramNames_[i]; }
    const std::string& getParamType(int i) const { return paramTypes_[i]; }
    void addParam(const std::string& nm, const std::string& ty);
    void setParams(std::vector<ParameterDefinition*> p) { params = std::move(p); }
    const std::vector<ParameterDefinition*>& getParams() const { return params; }

    void decode(Decoder& decoder, EquateTable* equateTable);
    void encode(Encoder& encoder) const;

private:
    HighFunction* highFunction = nullptr;
    LocalSymbolMap* localsyms = nullptr;
    std::string modelname;
    std::string injectname;
    std::string name;
    DataType* returntype = nullptr;
    void* returnstorage = nullptr;
    std::vector<ParameterDefinition*> params;
    std::vector<std::string> paramNames_;
    std::vector<std::string> paramTypes_;
    bool modellock = false;
    bool voidinputlock = false;
    bool outputlock = false;
    bool dotdotdot = false;
    int extrapop = UNKNOWN_EXTRAPOP;
    bool isinline = false;
    bool noreturn = false;
    bool custom = false;
    bool hasThisPtr = false;
    bool construct = false;
    bool destruct = false;
};

}  // namespace pcode
}  // namespace ghidra
