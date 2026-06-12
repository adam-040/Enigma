/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CategoryPath.cpp
/// \brief Category path implementation
#include <ghidra/CategoryPath.h>

namespace ghidra {

std::string CategoryPath::buildPath() const {
    if (isRoot()) {
        return DELIMITER_STRING;
    }
    std::string path;
    for (const auto& elem : elements_) {
        path += DELIMITER_STRING + escapeString(elem);
    }
    return path;
}

bool CategoryPath::endsWithNonEscapedDelimiter(const std::string& string) const {
    if (string.empty() || string.back() != DELIMITER_CHAR) return false;
    if (string.length() >= ESCAPED_DELIMITER_STRING.length() &&
        string.substr(string.length() - ESCAPED_DELIMITER_STRING.length()) == ESCAPED_DELIMITER_STRING) {
        return false;
    }
    return true;
}

int CategoryPath::findIndexOfLastNonEscapedDelimiter(const std::string& string) const {
    int escapedIndex = static_cast<int>(string.length());
    int delimiterIndex = escapedIndex;
    while (delimiterIndex > 0) {
        auto pos = string.rfind(ESCAPED_DELIMITER_STRING, escapedIndex - 1);
        escapedIndex = (pos == std::string::npos) ? -1 : static_cast<int>(pos);

        auto dpos = string.rfind(DELIMITER_CHAR, delimiterIndex - 1);
        delimiterIndex = (dpos == std::string::npos) ? -1 : static_cast<int>(dpos);

        if (delimiterIndex != escapedIndex + 1) {
            break;
        }
    }
    return delimiterIndex;
}

CategoryPath::CategoryPath(const std::string& path) {
    if (path.empty() || path == DELIMITER_STRING) {
        return;
    }
    if (path[0] != DELIMITER_CHAR) {
        throw std::invalid_argument("Paths must start with " + DELIMITER_STRING);
    }
    if (endsWithNonEscapedDelimiter(path)) {
        throw std::invalid_argument("Paths must not end with " + DELIMITER_STRING);
    }
    if (path.find(ILLEGAL_STRING) != std::string::npos) {
        throw std::invalid_argument("Paths must have non-empty elements");
    }

    int delimiterIndex = findIndexOfLastNonEscapedDelimiter(path);
    CategoryPath parentPath(path.substr(0, delimiterIndex));

    elements_ = parentPath.elements_;
    elements_.push_back(unescapeString(path.substr(delimiterIndex + 1)));
}

CategoryPath::CategoryPath(const CategoryPath& parent, const std::vector<std::string>& subPathElements) {
    if (subPathElements.empty()) {
        throw std::invalid_argument("Category list must contain at least one string name!");
    }
    elements_ = parent.elements_;
    elements_.insert(elements_.end(), subPathElements.begin(), subPathElements.end());
}

CategoryPath::CategoryPath(const CategoryPath& parent, const std::string& name) {
    elements_ = parent.elements_;
    elements_.push_back(name);
}

const CategoryPath& CategoryPath::ROOT() {
    static const CategoryPath root;
    return root;
}

std::string CategoryPath::escapeString(const std::string& nonEscapedString) {
    std::string result = nonEscapedString;
    size_t pos = 0;
    while ((pos = result.find(DELIMITER_STRING, pos)) != std::string::npos) {
        result.replace(pos, DELIMITER_STRING.length(), ESCAPED_DELIMITER_STRING);
        pos += ESCAPED_DELIMITER_STRING.length();
    }
    return result;
}

std::string CategoryPath::unescapeString(const std::string& escapedString) {
    std::string result = escapedString;
    size_t pos = 0;
    while ((pos = result.find(ESCAPED_DELIMITER_STRING, pos)) != std::string::npos) {
        result.replace(pos, ESCAPED_DELIMITER_STRING.length(), DELIMITER_STRING);
        pos += DELIMITER_STRING.length();
    }
    return result;
}

CategoryPath CategoryPath::extend(const std::vector<std::string>& subPathElements) const {
    if (subPathElements.empty()) return *this;
    return CategoryPath(*this, subPathElements);
}

CategoryPath CategoryPath::extend(const std::string& name) const {
    return CategoryPath(*this, name);
}

CategoryPath CategoryPath::getParent() const {
    if (isRoot()) {
        return CategoryPath();
    }
    CategoryPath p;
    p.elements_ = std::vector<std::string>(elements_.begin(), elements_.end() - 1);
    return p;
}

std::string CategoryPath::getName() const {
    if (isRoot()) return "";
    return elements_.back();
}

std::string CategoryPath::getPath() const {
    return buildPath();
}

std::string CategoryPath::getPath(const std::string& childName) const {
    if (childName.empty()) {
        throw std::invalid_argument("blank child name");
    }
    std::string path = getPath();
    if (!isRoot()) {
        path += DELIMITER_STRING;
    }
    path += escapeString(childName);
    return path;
}

bool CategoryPath::isAncestorOrSelf(const CategoryPath& candidateAncestorPath) const {
    if (candidateAncestorPath.isRoot()) {
        return true;
    }
    if (candidateAncestorPath.elements_.size() > elements_.size()) {
        return false;
    }
    for (size_t i = 0; i < candidateAncestorPath.elements_.size(); ++i) {
        if (candidateAncestorPath.elements_[i] != elements_[i]) {
            return false;
        }
    }
    return true;
}

std::size_t CategoryPath::hash() const {
    std::size_t h = 0;
    for (const auto& el : elements_) {
        h ^= std::hash<std::string>{}(el) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
}

std::string CategoryPath::toString() const {
    return getPath();
}

CategoryPath::CategoryPath() : elements_() {}

bool CategoryPath::operator<(const CategoryPath& other) const {
    if (elements_.size() != other.elements_.size()) {
        return elements_.size() < other.elements_.size();
    }
    for (size_t i = 0; i < elements_.size(); ++i) {
        if (elements_[i] != other.elements_[i]) {
            return elements_[i] < other.elements_[i];
        }
    }
    return false;
}

} // namespace ghidra
