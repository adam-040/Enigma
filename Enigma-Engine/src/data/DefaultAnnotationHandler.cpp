/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/DefaultAnnotationHandler.h>

namespace ghidra {

std::string DefaultAnnotationHandler::getPrefix(Enum* e, const std::string& member) const {
    return "";
}

std::string DefaultAnnotationHandler::getSuffix(Enum* e, const std::string& member) const {
    return "";
}

std::string DefaultAnnotationHandler::getPrefix(Composite* c, DataTypeComponent* dtc) const {
    return "";
}

std::string DefaultAnnotationHandler::getSuffix(Composite* c, DataTypeComponent* dtc) const {
    return "";
}

std::string DefaultAnnotationHandler::getDescription() const {
    return "Default C Annotations";
}

std::string DefaultAnnotationHandler::getLanguageName() const {
    return "C/C++";
}

std::vector<std::string> DefaultAnnotationHandler::getFileExtensions() const {
    return {"c", "h", "cpp"};
}

std::string DefaultAnnotationHandler::toString() const {
    return getLanguageName();
}

} // namespace ghidra
