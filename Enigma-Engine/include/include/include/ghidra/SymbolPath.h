/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SymbolPath.h
/// \brief Represents a parsed namespace path to a symbol
/// Translated from: ghidra.app.util.SymbolPath
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace ghidra {

class Symbol;
class Namespace;

class SymbolPath {
public:
    static constexpr const char* NAMESPACE_DELIMITER = "::";

    SymbolPath(const std::string& pathStr);
    explicit SymbolPath(const std::vector<std::string>& pathList);
    SymbolPath(const SymbolPath* parent, const std::string& name);
    explicit SymbolPath(Symbol* symbol);
    SymbolPath(Symbol* symbol, bool excludeLibrary);

    SymbolPath(const SymbolPath& other);
    SymbolPath& operator=(const SymbolPath& other);
    SymbolPath(SymbolPath&& other) noexcept = default;
    SymbolPath& operator=(SymbolPath&& other) noexcept = default;
    ~SymbolPath() = default;

    std::string getName() const { return symbolName_; }
    const SymbolPath* getParent() const { return parentPath_.get(); }
    std::string getParentPath() const;
    std::string getPath() const;
    std::vector<std::string> asList() const;
    std::string toString() const { return getPath(); }

    SymbolPath append(const SymbolPath& other) const;
    bool containsPathEntry(const std::string& text) const;
    int hashCode() const;
    bool operator==(const SymbolPath& other) const;
    bool operator!=(const SymbolPath& other) const { return !(*this == other); }
    bool operator<(const SymbolPath& other) const;
    bool matchesPathOf(Symbol* symbol) const;

    static std::string replaceInvalidChars(const std::string& name);

private:
    std::unique_ptr<SymbolPath> parentPath_;
    std::string symbolName_;

    SymbolPath(std::unique_ptr<SymbolPath> parent, const std::string& name);
    void addToList(std::vector<std::string>& list) const;
    static std::unique_ptr<SymbolPath> buildFromNamespace(Namespace* ns);
    static std::vector<std::string> parsePathString(const std::string& str);
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::SymbolPath> {
        std::size_t operator()(const ghidra::SymbolPath& sp) const { return sp.hashCode(); }
    };
}
