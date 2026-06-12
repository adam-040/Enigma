/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Symbol.cpp
/// \brief Symbol representation for program symbols
#include <ghidra/Symbol.h>
#include <ghidra/Reference.h>
#include <sstream>

namespace ghidra {

Symbol::Symbol(const std::string& name, Address address, Namespace* parent,
               SourceType source, SymbolType type, long id)
    : name_(name), address_(address), parent_(parent), source_(source), type_(type), id_(id) {}

bool Symbol::isGlobal() const {
    return parent_ && parent_->isGlobal();
}

std::string Symbol::getPathName() const {
    if (!parent_) return name_;
    std::string path = parent_->getPathName();
    if (path.empty() || path == "global") return name_;
    return path + "::" + name_;
}

std::string Symbol::toString() const {
    std::ostringstream ss;
    ss << name_ << " @ " << address_.toString() << " (" << symbolTypeToString(type_) << ")";
    return ss.str();
}

bool Symbol::operator==(const Symbol& other) const {
    return id_ == other.id_ && name_ == other.name_ && address_ == other.address_;
}

bool Symbol::operator!=(const Symbol& other) const {
    return !(*this == other);
}

} // namespace ghidra
