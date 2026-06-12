/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file Symbol.h
/// \brief Interface for a symbol which associates a string name with an address
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class Address;
class Namespace;
class Program;
class Reference;
class SourceType;
class SymbolType;
class SymbolIterator;

class Symbol {
public:
    virtual ~Symbol() = default;

    virtual std::shared_ptr<Address> getAddress() const = 0;
    virtual std::string getName() const = 0;
    virtual std::vector<std::string> getPath() const = 0;
    virtual Program* getProgram() const = 0;
    virtual std::string getName(bool includeNamespace) const = 0;
    virtual std::shared_ptr<Namespace> getParentNamespace() const = 0;
    virtual std::shared_ptr<Symbol> getParentSymbol() const = 0;
    virtual bool isDescendant(const std::shared_ptr<Namespace>& ns) const = 0;
    virtual bool isValidParent(const std::shared_ptr<Namespace>& parent) const = 0;
    virtual const SymbolType& getSymbolType() const = 0;
    virtual int getReferenceCount() const { return 0; }
    virtual bool hasReferences() const { return false; }
    virtual std::vector<std::shared_ptr<Reference>> getReferences() const { return {}; }

    virtual void setName(const std::string& newName, SourceType source) = 0;
    virtual void setNamespace(const std::shared_ptr<Namespace>& newNamespace) = 0;
    virtual void setNameAndNamespace(const std::string& newName, const std::shared_ptr<Namespace>& newNamespace, SourceType source) = 0;
    virtual bool delete_() = 0;

    virtual bool isPinned() const { return false; }
    virtual void setPinned(bool pinned) {}
    virtual bool isDynamic() const = 0;
    virtual bool isExternal() const = 0;
    virtual bool isPrimary() const = 0;
    virtual bool setPrimary() = 0;
    virtual bool isExternalEntryPoint() const { return false; }
    virtual int64_t getID() const = 0;
    virtual void* getObject() const = 0;  // generic object association
    virtual bool isGlobal() const = 0;
    virtual void setSource(SourceType source) = 0;
    virtual SourceType getSource() const = 0;
    virtual bool isDeleted() const = 0;
};

} // namespace ghidra
