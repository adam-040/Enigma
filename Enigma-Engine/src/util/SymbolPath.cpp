/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolPath.cpp
/// \brief Symbol path implementation
#include <ghidra/SymbolPath.h>
#include <ghidra/Symbol.h>
#include <ghidra/Namespace.h>
#include <ghidra/Library.h>
#include <ghidra/SymbolUtilities.h>

namespace ghidra {

SymbolPath::SymbolPath(std::unique_ptr<SymbolPath> parent, const std::string& name)
    : parentPath_(std::move(parent)), symbolName_(name) {}

std::vector<std::string> SymbolPath::parsePathString(const std::string& str) {
    if (str.empty()) {
        throw std::invalid_argument("Pathname cannot be empty!");
    }

    std::vector<std::string> result;
    size_t startIndex = 0;
    size_t i = 0;
    int templateLevel = 0;
    int parenthesesLevel = 0;

    for (i = 0; i + 1 < str.length(); ++i) {
        if (str[i] == ':' && str[i + 1] == ':') {
            if (templateLevel == 0 && parenthesesLevel == 0) {
                if (i > startIndex) {
                    result.push_back(str.substr(startIndex, i - startIndex));
                }
                startIndex = i + 2;
                ++i;
            }
        }
        else if (str[i] == '<') {
            ++templateLevel;
        }
        else if (str[i] == '>') {
            --templateLevel;
        }
        else if (str[i] == '(') {
            ++parenthesesLevel;
        }
        else if (str[i] == ')') {
            --parenthesesLevel;
        }
    }

    if (templateLevel != 0 || parenthesesLevel != 0) {
        result.clear();
        startIndex = 0;
        for (i = 0; i + 1 < str.length(); ++i) {
            if (str[i] == ':' && str[i + 1] == ':') {
                if (i > startIndex) {
                    result.push_back(str.substr(startIndex, i - startIndex));
                }
                startIndex = i + 2;
                ++i;
            }
        }
    }

    result.push_back(str.substr(startIndex));
    return result;
}

SymbolPath::SymbolPath(const std::string& pathStr)
    : SymbolPath(parsePathString(pathStr)) {}

SymbolPath::SymbolPath(const std::vector<std::string>& pathList) {
    if (pathList.empty()) {
        throw std::invalid_argument("Symbol list must contain at least one symbol name!");
    }
    symbolName_ = pathList.back();
    if (pathList.size() > 1) {
        std::vector<std::string> parentList(pathList.begin(), pathList.end() - 1);
        parentPath_ = std::make_unique<SymbolPath>(std::move(parentList));
    }
}

SymbolPath::SymbolPath(const SymbolPath* parent, const std::string& name) {
    if (parent) {
        parentPath_ = std::make_unique<SymbolPath>(*parent);
    }
    symbolName_ = name;
}

std::unique_ptr<SymbolPath> SymbolPath::buildFromNamespace(Namespace* ns) {
    if (ns == nullptr || ns->isGlobal()) {
        return nullptr;
    }
    auto parent = buildFromNamespace(ns->getParent());
    return std::unique_ptr<SymbolPath>(new SymbolPath(std::move(parent), ns->getName()));
}

SymbolPath::SymbolPath(Symbol* symbol, bool excludeLibrary) {
    symbolName_ = symbol->getName();
    Namespace* parentNs = symbol->getParentNamespace();
    if (parentNs == nullptr || parentNs->isGlobal()) {
        parentPath_ = nullptr;
    }
    else if (excludeLibrary && dynamic_cast<Library*>(parentNs)) {
        parentPath_ = nullptr;
    }
    else {
        parentPath_ = buildFromNamespace(parentNs);
    }
}

SymbolPath::SymbolPath(Symbol* symbol)
    : SymbolPath(symbol, false) {}

SymbolPath::SymbolPath(const SymbolPath& other) {
    symbolName_ = other.symbolName_;
    if (other.parentPath_) {
        parentPath_ = std::make_unique<SymbolPath>(*other.parentPath_);
    }
}

SymbolPath& SymbolPath::operator=(const SymbolPath& other) {
    if (this != &other) {
        symbolName_ = other.symbolName_;
        if (other.parentPath_) {
            parentPath_ = std::make_unique<SymbolPath>(*other.parentPath_);
        }
        else {
            parentPath_.reset();
        }
    }
    return *this;
}

std::string SymbolPath::getParentPath() const {
    if (!parentPath_) {
        return {};
    }
    return parentPath_->getPath();
}

std::string SymbolPath::getPath() const {
    if (parentPath_) {
        return parentPath_->getPath() + NAMESPACE_DELIMITER + symbolName_;
    }
    return symbolName_;
}

std::vector<std::string> SymbolPath::asList() const {
    std::vector<std::string> list;
    addToList(list);
    return list;
}

void SymbolPath::addToList(std::vector<std::string>& list) const {
    if (parentPath_) {
        parentPath_->addToList(list);
    }
    list.push_back(symbolName_);
}

SymbolPath SymbolPath::append(const SymbolPath& other) const {
    auto list = asList();
    auto otherList = other.asList();
    list.insert(list.end(), otherList.begin(), otherList.end());
    return SymbolPath(list);
}

bool SymbolPath::containsPathEntry(const std::string& text) const {
    auto list = asList();
    for (const auto& entry : list) {
        if (entry == text) return true;
    }
    return false;
}

int SymbolPath::hashCode() const {
    int prime = 31;
    int result = 1;
    result = prime * result + (parentPath_ ? parentPath_->hashCode() : 0);
    result = prime * result + std::hash<std::string>{}(symbolName_);
    return result;
}

bool SymbolPath::operator==(const SymbolPath& other) const {
    if (this == &other) return true;
    if (symbolName_ != other.symbolName_) return false;
    if (parentPath_ && other.parentPath_) return *parentPath_ == *other.parentPath_;
    return !parentPath_ && !other.parentPath_;
}

bool SymbolPath::operator<(const SymbolPath& other) const {
    if (!parentPath_ && other.parentPath_) return true;
    if (parentPath_ && !other.parentPath_) return false;
    if (parentPath_ && other.parentPath_) {
        if (*parentPath_ == *other.parentPath_) {
            return symbolName_ < other.symbolName_;
        }
        return *parentPath_ < *other.parentPath_;
    }
    return symbolName_ < other.symbolName_;
}

bool SymbolPath::matchesPathOf(Symbol* symbol) const {
    return *this == SymbolPath(symbol);
}

std::string SymbolPath::replaceInvalidChars(const std::string& name) {
    return SymbolUtilities::replaceInvalidChars(name, true);
}

} // namespace ghidra
