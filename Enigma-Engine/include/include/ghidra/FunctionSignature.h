/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionSignature.h
/// \brief Interface describing a function signature.
#pragma once

#include <string>
#include <vector>

namespace ghidra {

class DataType;
class ParameterDefinition;

/**
 * Interface describing all the things about a function that are portable
 * from one program to another.
 * Translated from: ghidra.program.model.listing.FunctionSignature
 */
class FunctionSignature {
public:
    static inline const std::string NORETURN_DISPLAY_STRING = "noreturn";
    static inline const std::string VAR_ARGS_DISPLAY_STRING = "...";
    static inline const std::string VOID_PARAM_DISPLAY_STRING = "void";

    virtual ~FunctionSignature() = default;

    virtual std::string getName() const = 0;
    virtual std::string getPrototypeString() const = 0;
    virtual std::string getPrototypeString(bool includeCallingConvention) const = 0;
    
    virtual std::vector<ParameterDefinition*> getArguments() const = 0;
    virtual DataType* getReturnType() const = 0;
    virtual std::string getComment() const = 0;
    
    virtual bool hasVarArgs() const = 0;
    virtual bool hasNoReturn() const = 0;
    
    // virtual PrototypeModel* getCallingConvention() const = 0; // Simplified
    
    virtual std::string getCallingConventionName() const = 0;
    
    virtual bool hasUnknownCallingConventionName() const {
        return getCallingConventionName() == "unknown";
    }

    virtual bool isEquivalentSignature(const FunctionSignature* signature) const = 0;
};

} // namespace ghidra
