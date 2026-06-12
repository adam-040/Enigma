/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DefaultAnnotationHandler.h
/// \brief Default C/C++ annotation handler.
/// Translated from: ghidra.program.model.data.DefaultAnnotationHandler
#pragma once

#include "AnnotationHandler.h"
#include <string>
#include <vector>

namespace ghidra {

class DefaultAnnotationHandler : public AnnotationHandler {
public:
    std::string getPrefix(Enum* e, const std::string& member) const override;
    std::string getSuffix(Enum* e, const std::string& member) const override;
    std::string getPrefix(Composite* c, DataTypeComponent* dtc) const override;
    std::string getSuffix(Composite* c, DataTypeComponent* dtc) const override;
    std::string getDescription() const override;
    std::string getLanguageName() const override;
    std::vector<std::string> getFileExtensions() const override;
    std::string toString() const override;
};

} // namespace ghidra
