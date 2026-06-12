/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Namespace.cpp
/// \brief Namespace representation for symbol organization
#include <ghidra/Namespace.h>

namespace ghidra {

Namespace::Namespace(const std::string& name, Namespace* parent, long id)
    : name_(name), parent_(parent), id_(id) {}

bool Namespace::isGlobal() const {
    return id_ == GLOBAL_NAMESPACE_ID || name_.empty();
}

std::string Namespace::getPathName() const {
    if (isGlobal()) return "global";
    if (!parent_ || parent_->isGlobal()) return name_;
    return parent_->getPathName() + "::" + name_;
}

bool Namespace::operator==(const Namespace& other) const {
    return id_ == other.id_ && name_ == other.name_;
}

bool Namespace::operator!=(const Namespace& other) const {
    return !(*this == other);
}

} // namespace ghidra
