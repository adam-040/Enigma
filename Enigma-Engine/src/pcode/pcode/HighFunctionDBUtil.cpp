/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunctionDBUtil.cpp
/// \brief Stub body for the HighFunctionDBUtil skeleton.
#include "ghidra/pcode/HighFunctionDBUtil.h"
#include "ghidra/pcode/HighFunction.h"
#include "ghidra/pcode/HighVariable.h"
#include "ghidra/HighSymbol.h"
#include "ghidra/ParameterDefinition.h"
#include "ghidra/Program.h"
#include "ghidra/Address.h"

namespace ghidra {
namespace pcode {

void HighFunctionDBUtil::updateDBType(const std::string& name, DataType* type) {
    (void)name; (void)type;
}

bool HighFunctionDBUtil::commitLocal(HighSymbol* sym, HighFunction* hfunc, bool storeNames) {
    (void)sym; (void)hfunc; (void)storeNames;
    return false;
}

void HighFunctionDBUtil::commitParam(HighVariable* param, bool storeNames) {
    (void)param; (void)storeNames;
}

bool HighFunctionDBUtil::convertHighParamToLocal(HighSymbol* param, HighFunction* hfunc) {
    (void)param; (void)hfunc;
    return false;
}

bool HighFunctionDBUtil::convertLocalToParam(HighSymbol* symbol, int newordinal,
                                             HighFunction* hfunc, bool hasThisPtr,
                                             bool setOrdinalOnAll) {
    (void)symbol; (void)newordinal; (void)hfunc;
    (void)hasThisPtr; (void)setOrdinalOnAll;
    return false;
}

void HighFunctionDBUtil::commitReturn(HighFunction* hfunc, bool storeNames) {
    (void)hfunc; (void)storeNames;
}

void HighFunctionDBUtil::commitParams(HighFunction* hfunc, bool storeNames) {
    (void)hfunc; (void)storeNames;
}

void HighFunctionDBUtil::updateDBFunction(HighFunction* hfunc, bool storeNames) {
    (void)hfunc; (void)storeNames;
}

std::string HighFunctionDBUtil::getAutoModelName(Program* program, Address* addr) {
    (void)program; (void)addr;
    return "__auto__";
}

HighSymbol* HighFunctionDBUtil::findHighSymbol(HighFunction* hfunc, HighVariable* hv) {
    (void)hfunc; (void)hv;
    return nullptr;
}

bool HighFunctionDBUtil::isEquivalent(HighSymbol* sym, ParameterDefinition* pd) {
    (void)sym; (void)pd;
    return false;
}

}  // namespace pcode
}  // namespace ghidra
