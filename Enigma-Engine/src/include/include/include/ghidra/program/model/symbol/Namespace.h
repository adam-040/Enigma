/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Namespace.h
/// \brief Interface for a namespace in the symbol hierarchy
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

class AddressSetView;
class Symbol;

class Namespace {
public:
    static constexpr int64_t GLOBAL_NAMESPACE_ID = 0;
    static constexpr const char* DELIMITER = "::";

    enum class Type {
        NAMESPACE = 0,
        LIBRARY,
        CLASS,
        FUNCTION
    };

    virtual ~Namespace() = default;

    virtual std::shared_ptr<Symbol> getSymbol() const = 0;
    virtual Type getType() const { return Type::NAMESPACE; }
    virtual bool isExternal() const = 0;
    virtual std::string getName() const = 0;
    virtual std::string getName(bool includeNamespacePath) const = 0;
    virtual std::vector<std::string> getPathList(bool omitLibrary) const;
    virtual int64_t getID() const = 0;
    virtual std::shared_ptr<Namespace> getParentNamespace() const = 0;
    virtual std::shared_ptr<AddressSetView> getBody() const = 0;
    virtual void setParentNamespace(const std::shared_ptr<Namespace>& parentNamespace) = 0;
    virtual bool isGlobal() const { return getID() == GLOBAL_NAMESPACE_ID; }
    virtual bool isLibrary() const { return false; }
};

// Inline implementation - uses getParentNamespace() recursion (implementations must provide it)
inline std::vector<std::string> Namespace::getPathList(bool omitLibrary) const {
    if (isGlobal()) return {};
    std::vector<std::string> list;
    // Walk up the chain using getParentNamespace()
    const Namespace* n = this;
    while (n != nullptr && !n->isGlobal() && !(omitLibrary && n->isLibrary())) {
        list.insert(list.begin(), n->getName());
        auto parent = n->getParentNamespace();
        if (parent && parent->isGlobal()) break;
        n = parent.get();
    }
    if (n && !n->isGlobal()) list.insert(list.begin(), n->getName());
    return list;
}

} // namespace ghidra
