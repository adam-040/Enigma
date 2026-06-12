/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReferenceManagerImpl.h
/// \brief Implementation of reference manager
/// Translated from: ghidra.program.database.references.ReferenceDBManager
#pragma once

#include <ghidra/ReferenceManager.h>
#include <ghidra/ManagerDB.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>

namespace ghidra {

class Program;
class TaskMonitor;

class ReferenceManagerImpl : public ReferenceManager, public ManagerDB {
public:
    ReferenceManagerImpl() = default;
    explicit ReferenceManagerImpl(Program* program);

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override;
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override;
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override;
    int getNumEntries() override { return getReferenceCount(); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "ReferenceManager"; }

    Reference* addReference(Reference* reference) override;
    Reference* addStackReference(Address fromAddr, int opIndex, int stackOffset,
                                  const RefType* type, SourceType source) override;
    Reference* addRegisterReference(Address fromAddr, int opIndex, Register* reg,
                                     const RefType* type, SourceType source) override;
    Reference* addMemoryReference(Address fromAddr, Address toAddr, const RefType* type,
                                   SourceType source, int opIndex) override;
    Reference* addOffsetMemReference(Address fromAddr, Address toAddr, bool toAddrIsBase,
                                      long offset, const RefType* type,
                                      SourceType source, int opIndex) override;
    Reference* addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
                                       const RefType* type, SourceType source,
                                       int opIndex) override;
    Reference* addExternalReference(Address fromAddr, const std::string& libraryName,
                                     const std::string& extLabel, Address extAddr,
                                     SourceType source, int opIndex,
                                     const RefType* type) override;
    Reference* addExternalReference(Address fromAddr, Namespace* extNamespace,
                                     const std::string& extLabel, Address extAddr,
                                     SourceType source, int opIndex,
                                     const RefType* type) override;
    Reference* addExternalReference(Address fromAddr, int opIndex,
                                     ExternalLocation* location,
                                     SourceType source, const RefType* type) override;

    void removeAllReferencesFrom(Address beginAddr, Address endAddr) override;
    void removeAllReferencesFrom(Address fromAddr) override;
    void removeAllReferencesTo(Address toAddr) override;

    std::vector<Reference*> getReferencesTo(Variable* var) override;
    Variable* getReferencedVariable(Reference* reference) override;

    void setPrimary(Reference* ref, bool isPrimary) override;
    bool hasFlowReferencesFrom(Address addr) override;
    std::vector<Reference*> getFlowReferencesFrom(Address addr) override;

    std::vector<Reference*> getReferencesTo(Address addr) override;
    std::unique_ptr<AddressIterator> getReferenceSourceIterator(const AddressSetView& addrSet, bool forward) override;
    std::vector<Reference*> getReferenceIterator(Address startAddr) override;
    Reference* getReference(Address fromAddr, Address toAddr, int opIndex) override;
    std::vector<Reference*> getReferencesFrom(Address addr) override;
    std::vector<Reference*> getReferencesFrom(Address fromAddr, int opIndex) override;
    bool hasReferencesFrom(Address fromAddr, int opIndex) override;
    bool hasReferencesFrom(Address fromAddr) override;
    Reference* getPrimaryReferenceFrom(Address addr, int opIndex) override;

    int getReferenceCountTo(Address toAddr) override;
    int getReferenceCountFrom(Address fromAddr) override;
    int getReferenceDestinationCount() override;
    int getReferenceSourceCount() override;
    bool hasReferencesTo(Address toAddr) override;

    Reference* updateRefType(Reference* ref, const RefType* refType) override;
    void setAssociation(Symbol* s, Reference* ref) override;
    void removeAssociation(Reference* ref) override;
    bool deleteReference(Reference* ref) override;
    int8_t getReferenceLevel(Address toAddr) override;
    int getReferenceCount() override { return static_cast<int>(references_.size()); }
    std::vector<Reference*> getAllReferences() const override;

private:
    void removeFromIndex(const std::string& key, Reference* ref,
                         std::unordered_map<std::string, std::vector<Reference*>>& index);

    Program* program_ = nullptr;
    std::unordered_map<long, std::unique_ptr<Reference>> references_;
    std::unordered_map<std::string, std::vector<Reference*>> refsFrom_;
    std::unordered_map<std::string, std::vector<Reference*>> refsTo_;
    long nextID_ = 1;
    int revision_ = 0;
};

} // namespace ghidra
