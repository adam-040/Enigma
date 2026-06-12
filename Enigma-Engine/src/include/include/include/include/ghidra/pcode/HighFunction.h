/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunction.h
/// \brief High-level abstraction associated with a low level function.
/// Translated from: ghidra.program.model.pcode.HighFunction
#pragma once

#include <ghidra/PcodeSyntaxTree.h>
#include <ghidra/Address.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/LocalSymbolMap.h>
#include <ghidra/GlobalSymbolMap.h>
#include <ghidra/EquateTable.h>
#include <ghidra/pcode/FunctionPrototype.h>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {
namespace pcode {

class FunctionPrototype;
class HighParam;
class HighVariable;
}

class LocalSymbolMap;
class GlobalSymbolMap;
namespace pcode {

/**
 * HighFunction: high-level abstraction associated with a low level function.
 *
 * The decompiler produces this object from a Function.  It owns a separate
 * PcodeSyntaxTree populated by ActionManager-based high-level optimizations
 * plus the local/global symbol maps and equate table.
 */
class HighFunction : public PcodeSyntaxTree {
public:
    HighFunction();
    HighFunction(void* func, void* language, void* compilerSpec, void* dtManager,
                 EquateTable* equateTable);
    ~HighFunction() override = default;

    void* getFunction() const { return func; }
    void* getLanguage() const { return language; }
    void* getCompilerSpec() const { return compilerSpec; }
    void* getDataTypeManager() const { return dtManager; }

    EquateTable* getEquateTable() const { return equateTable; }
    ::ghidra::LocalSymbolMap* getLocalSymbolMap() const { return localSymbolMap.get(); }
    ::ghidra::GlobalSymbolMap* getGlobalSymbolMap() const { return globalSymbolMap.get(); }
    pcode::FunctionPrototype* getFunctionPrototype() const { return functionPrototype.get(); }

    void setFunction(void* f) { func = f; }
    void setEquateTable(EquateTable* et) { equateTable = et; }
    void setLocalSymbolMap(std::unique_ptr<::ghidra::LocalSymbolMap> lsm) { localSymbolMap = std::move(lsm); }
    void setGlobalSymbolMap(std::unique_ptr<::ghidra::GlobalSymbolMap> gsm) { globalSymbolMap = std::move(gsm); }
    void setFunctionPrototype(std::unique_ptr<pcode::FunctionPrototype> fp) { functionPrototype = std::move(fp); }

    int getSize() const { return size; }
    void setSize(int s) { size = s; }

    const std::vector<HighParam*>& getParamList() const { return paramList; }
    void addParam(HighParam* p) { paramList.push_back(p); }

    HighVariable* getReturn() const { return returnVar; }
    void setReturn(HighVariable* r) { returnVar = r; }

    const std::vector<HighVariable*>& getVariables() const { return variables; }
    void addVariable(HighVariable* v) { variables.push_back(v); }

    void decode(Decoder& decoder);
    void encode(Encoder& encoder) const;

    void grabFromFunction();
    void releaseToFunction();
    void cleanSymbols();

private:
    void* func;
    void* language;
    void* compilerSpec;
    void* dtManager;
    EquateTable* equateTable;
    std::unique_ptr<::ghidra::LocalSymbolMap> localSymbolMap;
    std::unique_ptr<::ghidra::GlobalSymbolMap> globalSymbolMap;
    std::unique_ptr<pcode::FunctionPrototype> functionPrototype;
    int size;
    std::vector<HighParam*> paramList;
    HighVariable* returnVar;
    std::vector<HighVariable*> variables;
};

}  // namespace pcode
}  // namespace ghidra
