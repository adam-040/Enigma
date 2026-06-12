/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file ReferenceManager.h
/// \brief Interface for managing references between addresses
#pragma once

#include <memory>
#include <vector>

namespace ghidra {

class Address;
class Reference;
class ReferenceIterator;
class Symbol;

class ReferenceManager {
public:
    virtual ~ReferenceManager() = default;

    virtual std::shared_ptr<Reference> addMemoryReference(const std::shared_ptr<Address>& from, const std::shared_ptr<Address>& to, int refType, int operandIndex) = 0;
    virtual std::shared_ptr<Reference> addOffsetReference(const std::shared_ptr<Address>& from, const std::shared_ptr<Address>& to, bool isBase, int refType, int operandIndex) = 0;
    virtual std::shared_ptr<Reference> addStackReference(const std::shared_ptr<Address>& from, int32_t stackOffset, int refType, int operandIndex) = 0;
    virtual std::shared_ptr<Reference> addExternalReference(const std::shared_ptr<Address>& from, const std::shared_ptr<Address>& to, int refType, int operandIndex) = 0;
    virtual void deleteReference(const std::shared_ptr<Reference>& ref) = 0;
    virtual void removeAllReferencesFrom(const std::shared_ptr<Address>& from) = 0;

    virtual std::shared_ptr<Reference> getReference(const std::shared_ptr<Address>& from, const std::shared_ptr<Address>& to, int operandIndex) = 0;
    virtual std::vector<std::shared_ptr<Reference>> getReferencesFrom(const std::shared_ptr<Address>& addr) = 0;
    virtual std::vector<std::shared_ptr<Reference>> getReferencesTo(const std::shared_ptr<Address>& addr) = 0;
    virtual int getReferenceCountTo(const std::shared_ptr<Address>& addr) = 0;

    virtual bool hasReferencesFrom(const std::shared_ptr<Address>& addr) = 0;
    virtual bool hasReferencesTo(const std::shared_ptr<Address>& addr) = 0;
};

} // namespace ghidra
