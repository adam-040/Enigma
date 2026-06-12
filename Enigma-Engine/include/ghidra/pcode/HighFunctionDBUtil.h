/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighFunctionDBUtil.h
/// \brief Skeleton port of HighFunctionDBUtil (958 lines Java).
/// \details Only the public surface is declared. The full body is intentionally
///          stubbed: callers can wire the static methods in incrementally as
///          their backing types (DataTypeManager, Function, etc.) come online.
/// Translated from: ghidra.program.model.pcode.HighFunctionDBUtil
#pragma once

#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class DataType;
class Function;
class Program;
class HighSymbol;
class HighVariable;
class ParameterDefinition;
class VariableStorage;
class Address;

namespace pcode {

class HighFunction;
class HighVariable;

/**
 * Bridge between a pcode HighFunction view and the underlying ProgramDB.
 *
 * Java's full implementation handles committing local symbols back to the
 * Function, equivalence checks, parameter promotion, and storage fixups.
 * The C++ skeleton here exposes the same static API surface; bodies are
 * minimal no-ops until the missing pcode infrastructure is ported.
 */
class HighFunctionDBUtil {
public:
    /// Direct update of a DataType in the function's signature.
    static void updateDBType(const std::string& name, DataType* type);

    /// Commit a HighSymbol back to the ProgramDB.
    static bool commitLocal(HighSymbol* sym, HighFunction* hfunc, bool storeNames);

    /// Commit a HighVariable's data type back to the source HighSymbol.
    static void commitParam(HighVariable* param, bool storeNames);

    /// Promote an inferred parameter to a real local variable.
    static bool convertHighParamToLocal(HighSymbol* param, HighFunction* hfunc);

    /// Convert a HighSymbol (local) to a parameter.
    static bool convertLocalToParam(HighSymbol* symbol, int newordinal,
                                    HighFunction* hfunc, bool hasThisPtr,
                                    bool setOrdinalOnAll);

    /// Push the HighFunction's prototype back to the underlying Function.
    static void commitReturn(HighFunction* hfunc, bool storeNames);
    static void commitParams(HighFunction* hfunc, bool storeNames);
    static void updateDBFunction(HighFunction* hfunc, bool storeNames);

    /// Best-effort model name for an Address.
    static std::string getAutoModelName(Program* program, Address* addr);

    /// Look up a HighSymbol by HighVariable instance.
    static HighSymbol* findHighSymbol(HighFunction* hfunc, HighVariable* hv);

    /// Equivalence between a HighSymbol and a ParameterDefinition.
    static bool isEquivalent(HighSymbol* sym, ParameterDefinition* pd);
};

}  // namespace pcode
}  // namespace ghidra
