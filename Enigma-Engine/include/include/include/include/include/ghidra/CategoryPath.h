/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CategoryPath.h
/// \brief Represents the full path to a particular data type
/// Translated from: ghidra.program.model.data.CategoryPath
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <algorithm>

namespace ghidra {

class CategoryPath {
public:
    static constexpr char DELIMITER_CHAR = '/';
    static inline const std::string DELIMITER_STRING = "/";
    static inline const std::string ESCAPED_DELIMITER_STRING = "\\/";

private:
    static inline const std::string ILLEGAL_STRING = "//";
    std::vector<std::string> elements_;

    std::string buildPath() const;
    bool endsWithNonEscapedDelimiter(const std::string& string) const;
    int findIndexOfLastNonEscapedDelimiter(const std::string& string) const;

public:
    CategoryPath();
    explicit CategoryPath(const std::string& path);
    CategoryPath(const CategoryPath& parent, const std::vector<std::string>& subPathElements);
    CategoryPath(const CategoryPath& parent, const std::string& name);

    static const CategoryPath& ROOT();
    static std::string escapeString(const std::string& nonEscapedString);
    static std::string unescapeString(const std::string& escapedString);

    CategoryPath extend(const std::vector<std::string>& subPathElements) const;
    CategoryPath extend(const std::string& name) const;

    bool isRoot() const { return elements_.empty(); }
    CategoryPath getParent() const;
    std::string getName() const;
    std::string getPath() const;
    std::string getPath(const std::string& childName) const;
    bool isAncestorOrSelf(const CategoryPath& candidateAncestorPath) const;
    std::vector<std::string> asList() const { return elements_; }

    bool operator==(const CategoryPath& other) const { return elements_ == other.elements_; }
    bool operator!=(const CategoryPath& other) const { return elements_ != other.elements_; }
    bool operator<(const CategoryPath& other) const;

    std::size_t hash() const;
    std::string toString() const;
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::CategoryPath> {
        std::size_t operator()(const ghidra::CategoryPath& cp) const { return cp.hash(); }
    };
}
