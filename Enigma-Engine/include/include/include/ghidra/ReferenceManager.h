/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReferenceManager.h
/// \brief Interface for managing references
/// Translated from: ghidra.program.model.symbol.ReferenceManager
#pragma once

#include <ghidra/Address.h>
#include <ghidra/Reference.h>
#include <ghidra/SourceType.h>
#include <vector>
#include <string>
#include <memory>

namespace ghidra {

class RefType;
class Register;
class Symbol;
class ExternalLocation;
class Namespace;
class Variable;
class AddressSetView;
class AddressIterator;

class ReferenceManager {
public:
    virtual ~ReferenceManager() = default;

    virtual Reference* addReference(Reference* reference) = 0;
    virtual Reference* addStackReference(Address fromAddr, int opIndex, int stackOffset,
                                          const RefType* type, SourceType source) = 0;
    virtual Reference* addRegisterReference(Address fromAddr, int opIndex, Register* reg,
                                             const RefType* type, SourceType source) = 0;
    virtual Reference* addMemoryReference(Address fromAddr, Address toAddr, const RefType* type,
                                           SourceType source, int opIndex) = 0;
    virtual Reference* addOffsetMemReference(Address fromAddr, Address toAddr, bool toAddrIsBase,
                                              long offset, const RefType* type,
                                              SourceType source, int opIndex) = 0;
    virtual Reference* addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
                                               const RefType* type, SourceType source,
                                               int opIndex) = 0;
    virtual Reference* addExternalReference(Address fromAddr, const std::string& libraryName,
                                             const std::string& extLabel, Address extAddr,
                                             SourceType source, int opIndex,
                                             const RefType* type) = 0;
    virtual Reference* addExternalReference(Address fromAddr, Namespace* extNamespace,
                                             const std::string& extLabel, Address extAddr,
                                             SourceType source, int opIndex,
                                             const RefType* type) = 0;
    virtual Reference* addExternalReference(Address fromAddr, int opIndex,
                                             ExternalLocation* location,
                                             SourceType source, const RefType* type) = 0;

    virtual void removeAllReferencesFrom(Address beginAddr, Address endAddr) = 0;
    virtual void removeAllReferencesFrom(Address fromAddr) = 0;
    virtual void removeAllReferencesTo(Address toAddr) = 0;

    virtual std::vector<Reference*> getReferencesTo(Variable* var) = 0;
    virtual Variable* getReferencedVariable(Reference* reference) = 0;

    virtual void setPrimary(Reference* ref, bool isPrimary) = 0;
    virtual bool hasFlowReferencesFrom(Address addr) = 0;
    virtual std::vector<Reference*> getFlowReferencesFrom(Address addr) = 0;

    virtual std::vector<Reference*> getReferencesTo(Address addr) = 0;
    virtual std::unique_ptr<AddressIterator> getReferenceSourceIterator(const AddressSetView& addrSet, bool forward) = 0;
    virtual std::vector<Reference*> getReferenceIterator(Address startAddr) = 0;
    virtual Reference* getReference(Address fromAddr, Address toAddr, int opIndex) = 0;
    virtual std::vector<Reference*> getReferencesFrom(Address addr) = 0;
    virtual std::vector<Reference*> getReferencesFrom(Address fromAddr, int opIndex) = 0;
    virtual bool hasReferencesFrom(Address fromAddr, int opIndex) = 0;
    virtual bool hasReferencesFrom(Address fromAddr) = 0;
    virtual Reference* getPrimaryReferenceFrom(Address addr, int opIndex) = 0;

    virtual int getReferenceCountTo(Address toAddr) = 0;
    virtual int getReferenceCountFrom(Address fromAddr) = 0;
    virtual int getReferenceDestinationCount() = 0;
    virtual int getReferenceSourceCount() = 0;
    virtual bool hasReferencesTo(Address toAddr) = 0;

    virtual Reference* updateRefType(Reference* ref, const RefType* refType) = 0;
    virtual void setAssociation(Symbol* s, Reference* ref) = 0;
    virtual void removeAssociation(Reference* ref) = 0;
    virtual bool deleteReference(Reference* ref) = 0;
    virtual int8_t getReferenceLevel(Address toAddr) = 0;
    virtual int getReferenceCount() = 0;
    virtual std::vector<Reference*> getAllReferences() const = 0;
};

} // namespace ghidra
