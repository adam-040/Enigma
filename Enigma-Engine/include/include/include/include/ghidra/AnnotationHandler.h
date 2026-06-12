/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AnnotationHandler.h
/// \brief Interface providing prefix/suffix annotations for C-like languages.
/// Translated from: ghidra.program.model.data.AnnotationHandler
#pragma once

#include <string>
#include <vector>

namespace ghidra {

class Enum;
class Composite;
class DataTypeComponent;

class AnnotationHandler {
public:
    virtual ~AnnotationHandler() = default;

    virtual std::string getPrefix(Enum* e, const std::string& member) const = 0;
    virtual std::string getSuffix(Enum* e, const std::string& member) const = 0;
    virtual std::string getPrefix(Composite* c, DataTypeComponent* dtc) const = 0;
    virtual std::string getSuffix(Composite* c, DataTypeComponent* dtc) const = 0;
    virtual std::string getDescription() const = 0;
    virtual std::string getLanguageName() const = 0;
    virtual std::vector<std::string> getFileExtensions() const = 0;
    virtual std::string toString() const = 0;
};

} // namespace ghidra
