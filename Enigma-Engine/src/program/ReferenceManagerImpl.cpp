/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReferenceManagerImpl.cpp
/// \brief Implementation of reference manager
/// Translated from: ghidra.program.database.references.ReferenceDBManager

#include <ghidra/ReferenceManagerImpl.h>
#include <ghidra/MemReferenceImpl.h>
#include <ghidra/StackReferenceImpl.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/Program.h>
#include <ghidra/RefType.h>
#include <ghidra/Register.h>
#include <ghidra/Symbol.h>
#include <ghidra/Variable.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressIterator.h>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

ReferenceManagerImpl::ReferenceManagerImpl(Program* program)
    : program_(program) {}

void ReferenceManagerImpl::clearCache(bool all) {
    if (all) {
        references_.clear();
        refsFrom_.clear();
        refsTo_.clear();
    }
}

void ReferenceManagerImpl::deleteAddressRange(const Address& startAddr, const Address& endAddr,
                                               TaskMonitor* monitor) {
    removeAllReferencesFrom(startAddr, endAddr);
}

void ReferenceManagerImpl::moveAddressRange(const Address& fromAddr, const Address& toAddr,
                                             uint64_t length, TaskMonitor* monitor) {
    // Stub: address range relocation not yet implemented
}

bool ReferenceManagerImpl::hasDuplicate(Address fromAddr, Address toAddr, int opIndex) const {
    auto it = refsFrom_.find(fromAddr.toString());
    if (it == refsFrom_.end()) return false;
    for (auto* ref : it->second) {
        if (ref->getOperandIndex() == opIndex && ref->getToAddress() == toAddr) {
            return true;
        }
    }
    return false;
}

Reference* ReferenceManagerImpl::addReference(Reference* reference) {
    if (hasDuplicate(reference->getFromAddress(), reference->getToAddress(),
                     reference->getOperandIndex())) {
        ++duplicateCount_;
        return nullptr;
    }
    long id = nextID_++;
    auto memRef = std::make_unique<MemReferenceImpl>(
        reference->getFromAddress(),
        reference->getToAddress(),
        reference->getReferenceType(),
        reference->getSource(),
        reference->getOperandIndex(),
        reference->isPrimary(),
        id
    );
    Reference* raw = memRef.get();
    references_[id] = std::move(memRef);
    refsFrom_[reference->getFromAddress().toString()].push_back(raw);
    refsTo_[reference->getToAddress().toString()].push_back(raw);
    return raw;
}

Reference* ReferenceManagerImpl::addStackReference(Address fromAddr, int opIndex,
                                                     int stackOffset, const RefType* type,
                                                     SourceType source) {
    long id = nextID_++;
    auto ref = std::make_unique<StackReferenceImpl>(fromAddr, stackOffset, type, source, opIndex, true, id);
    Reference* raw = ref.get();
    references_[id] = std::move(ref);
    refsFrom_[fromAddr.toString()].push_back(raw);
    return raw;
}

Reference* ReferenceManagerImpl::addRegisterReference(Address fromAddr, int opIndex,
                                                       Register* reg, const RefType* type,
                                                       SourceType source) {
    Address regAddr = reg->getAddress();
    long id = nextID_++;
    auto ref = std::make_unique<MemReferenceImpl>(fromAddr, regAddr, type, source, opIndex, true, id);
    Reference* raw = ref.get();
    references_[id] = std::move(ref);
    refsFrom_[fromAddr.toString()].push_back(raw);
    return raw;
}

Reference* ReferenceManagerImpl::addMemoryReference(Address fromAddr, Address toAddr,
                                                     const RefType* type, SourceType source,
                                                     int opIndex) {
    if (hasDuplicate(fromAddr, toAddr, opIndex)) {
        ++duplicateCount_;
        return nullptr;
    }
    long id = nextID_++;
    auto ref = std::make_unique<MemReferenceImpl>(fromAddr, toAddr, type, source, opIndex, true, id);
    Reference* raw = ref.get();
    references_[id] = std::move(ref);
    refsFrom_[fromAddr.toString()].push_back(raw);
    refsTo_[toAddr.toString()].push_back(raw);
    return raw;
}

Reference* ReferenceManagerImpl::addOffsetMemReference(Address fromAddr, Address toAddr,
                                                        bool toAddrIsBase, long offset,
                                                        const RefType* type, SourceType source,
                                                        int opIndex) {
    // Stub: offset reference not yet implemented
    return addMemoryReference(fromAddr, toAddr, type, source, opIndex);
}

Reference* ReferenceManagerImpl::addShiftedMemReference(Address fromAddr, Address toAddr,
                                                         int shiftValue, const RefType* type,
                                                         SourceType source, int opIndex) {
    // Stub: shifted reference not yet implemented
    return addMemoryReference(fromAddr, toAddr, type, source, opIndex);
}

Reference* ReferenceManagerImpl::addExternalReference(Address fromAddr,
                                                       const std::string& libraryName,
                                                       const std::string& extLabel,
                                                       Address extAddr, SourceType source,
                                                       int opIndex, const RefType* type) {
    // Resolve (library, label) against the program's external manager,
    // creating the location when the caller supplies an external address.
    ExternalLocation* location = nullptr;
    if (program_) {
        if (ExternalManager* em = program_->getExternalManager()) {
            location = em->getExternalLocation(libraryName, extLabel);
            if (!location && extAddr.isValid()) {
                location = em->addExternalLocation(libraryName, extLabel, extAddr);
            }
        }
    }
    if (!location) {
        return addMemoryReference(fromAddr, extAddr.isValid() ? extAddr : fromAddr,
                                  type ? type : &RefTypes::DATA, source, opIndex);
    }
    return addExternalReference(fromAddr, opIndex, location, source,
                                type ? type : &RefTypes::DATA);
}

Reference* ReferenceManagerImpl::addExternalReference(Address fromAddr, Namespace* extNamespace,
                                                       const std::string& extLabel,
                                                       Address extAddr, SourceType source,
                                                       int opIndex, const RefType* type) {
    return addExternalReference(fromAddr, extNamespace ? extNamespace->getName() : "",
                                extLabel, extAddr, source, opIndex, type);
}

Reference* ReferenceManagerImpl::addExternalReference(Address fromAddr, int opIndex,
                                                       ExternalLocation* location,
                                                       SourceType source, const RefType* type) {
    if (!location || !location->getAddress().isValid()) {
        return nullptr;
    }
    Address toAddr = location->getAddress();
    if (hasDuplicate(fromAddr, toAddr, opIndex)) {
        ++duplicateCount_;
        return nullptr;
    }
    long id = nextID_++;
    auto ref = std::make_unique<MemReferenceImpl>(fromAddr, toAddr,
                                                  type ? type : &RefTypes::DATA, source,
                                                  opIndex, true, id);
    ref->setExternal(true);
    if (location->getSymbolID() >= 0) {
        ref->setSymbolID(location->getSymbolID());
    }
    Reference* raw = ref.get();
    references_[id] = std::move(ref);
    refsFrom_[fromAddr.toString()].push_back(raw);
    refsTo_[toAddr.toString()].push_back(raw);
    return raw;
}

void ReferenceManagerImpl::removeAllReferencesFrom(Address beginAddr, Address endAddr) {
    std::vector<long> idsToRemove;
    for (auto& pair : references_) {
        auto* ref = pair.second.get();
        Address from = ref->getFromAddress();
        if (from >= beginAddr && from <= endAddr) {
            idsToRemove.push_back(pair.first);
        }
    }
    for (long id : idsToRemove) {
        auto it = references_.find(id);
        if (it != references_.end()) {
            refsFrom_.erase(it->second->getFromAddress().toString());
            refsTo_.erase(it->second->getToAddress().toString());
            references_.erase(it);
        }
    }
}

void ReferenceManagerImpl::removeAllReferencesFrom(Address fromAddr) {
    auto it = refsFrom_.find(fromAddr.toString());
    if (it != refsFrom_.end()) {
        for (auto* ref : it->second) {
            refsTo_[ref->getToAddress().toString()].erase(
                std::remove(refsTo_[ref->getToAddress().toString()].begin(),
                            refsTo_[ref->getToAddress().toString()].end(), ref),
                refsTo_[ref->getToAddress().toString()].end());
            for (auto& pair : references_) {
                if (pair.second.get() == ref) {
                    references_.erase(pair.first);
                    break;
                }
            }
        }
        refsFrom_.erase(it);
    }
}

void ReferenceManagerImpl::removeAllReferencesTo(Address toAddr) {
    auto it = refsTo_.find(toAddr.toString());
    if (it != refsTo_.end()) {
        for (auto* ref : it->second) {
            refsFrom_[ref->getFromAddress().toString()].erase(
                std::remove(refsFrom_[ref->getFromAddress().toString()].begin(),
                            refsFrom_[ref->getFromAddress().toString()].end(), ref),
                refsFrom_[ref->getFromAddress().toString()].end());
            for (auto& pair : references_) {
                if (pair.second.get() == ref) {
                    references_.erase(pair.first);
                    break;
                }
            }
        }
        refsTo_.erase(it);
    }
}

std::vector<Reference*> ReferenceManagerImpl::getReferencesTo(Variable* var) {
    if (!var || !var->isStackVariable()) return {};
    int stackOffset = var->getStackOffset();
    Address fromBase = var->getMinAddress();
    std::vector<Reference*> result;
    for (const auto& [id, ref] : references_) {
        if (ref->isStackReference() &&
            ref->getOperandIndex() >= 0) {
            auto* sr = dynamic_cast<StackReferenceImpl*>(ref.get());
            if (sr && sr->getStackOffset() == stackOffset) {
                result.push_back(ref.get());
            }
        }
    }
    return result;
}

Variable* ReferenceManagerImpl::getReferencedVariable(Reference* reference) {
    if (!reference || !reference->isStackReference()) return nullptr;
    // Walk all functions to find a variable at the stack offset
    // In a full impl this would use a variable-to-ref index
    return nullptr;
}

void ReferenceManagerImpl::setPrimary(Reference* ref, bool isPrimary) {
    if (auto* memRef = dynamic_cast<MemReferenceImpl*>(ref)) {
        memRef->setPrimary(isPrimary);
    }
}

bool ReferenceManagerImpl::hasFlowReferencesFrom(Address addr) {
    auto it = refsFrom_.find(addr.toString());
    if (it == refsFrom_.end()) return false;
    for (auto* ref : it->second) {
        if (ref->getReferenceType() != nullptr && ref->getReferenceType()->isFlow()) return true;
    }
    return false;
}

std::vector<Reference*> ReferenceManagerImpl::getFlowReferencesFrom(Address addr) {
    std::vector<Reference*> result;
    auto it = refsFrom_.find(addr.toString());
    if (it == refsFrom_.end()) return result;
    for (auto* ref : it->second) {
        if (ref->getReferenceType() != nullptr && ref->getReferenceType()->isFlow()) {
            result.push_back(ref);
        }
    }
    return result;
}

std::vector<Reference*> ReferenceManagerImpl::getReferencesTo(Address addr) {
    auto it = refsTo_.find(addr.toString());
    return (it != refsTo_.end()) ? it->second : std::vector<Reference*>{};
}

std::unique_ptr<AddressIterator> ReferenceManagerImpl::getReferenceSourceIterator(
    const AddressSetView& addrSet, bool forward) {
    std::vector<Address> result;
    for (const auto& refsPair : refsFrom_) {
        if (refsPair.second.empty()) continue;
        Address fromAddr = refsPair.second.front()->getFromAddress();
        if (addrSet.contains(fromAddr)) {
            result.push_back(fromAddr);
        }
    }
    if (forward) {
        std::sort(result.begin(), result.end());
    } else {
        std::sort(result.begin(), result.end(), std::greater<Address>());
    }
    return std::make_unique<AddressIterator>(result);
}

std::vector<Reference*> ReferenceManagerImpl::getReferenceIterator(Address startAddr) {
    // Stub: simple linear scan
    std::vector<Reference*> result;
    for (auto& pair : references_) {
        if (pair.second->getFromAddress() >= startAddr) {
            result.push_back(pair.second.get());
        }
    }
    std::sort(result.begin(), result.end(),
              [](Reference* a, Reference* b) {
                  return a->getFromAddress() < b->getFromAddress();
              });
    return result;
}

Reference* ReferenceManagerImpl::getReference(Address fromAddr, Address toAddr, int opIndex) {
    auto it = refsFrom_.find(fromAddr.toString());
    if (it == refsFrom_.end()) return nullptr;
    for (auto* ref : it->second) {
        if (ref->getToAddress() == toAddr && ref->getOperandIndex() == opIndex) {
            return ref;
        }
    }
    return nullptr;
}

std::vector<Reference*> ReferenceManagerImpl::getReferencesFrom(Address addr) {
    auto it = refsFrom_.find(addr.toString());
    return (it != refsFrom_.end()) ? it->second : std::vector<Reference*>{};
}

std::vector<Reference*> ReferenceManagerImpl::getReferencesFrom(Address fromAddr, int opIndex) {
    std::vector<Reference*> result;
    auto it = refsFrom_.find(fromAddr.toString());
    if (it == refsFrom_.end()) return result;
    for (auto* ref : it->second) {
        if (ref->getOperandIndex() == opIndex) result.push_back(ref);
    }
    return result;
}

bool ReferenceManagerImpl::hasReferencesFrom(Address fromAddr, int opIndex) {
    auto it = refsFrom_.find(fromAddr.toString());
    if (it == refsFrom_.end()) return false;
    for (auto* ref : it->second) {
        if (ref->getOperandIndex() == opIndex) return true;
    }
    return false;
}

bool ReferenceManagerImpl::hasReferencesFrom(Address fromAddr) {
    return refsFrom_.find(fromAddr.toString()) != refsFrom_.end();
}

Reference* ReferenceManagerImpl::getPrimaryReferenceFrom(Address addr, int opIndex) {
    auto it = refsFrom_.find(addr.toString());
    if (it == refsFrom_.end()) return nullptr;
    for (auto* ref : it->second) {
        if (ref->getOperandIndex() == opIndex && ref->isPrimary()) return ref;
    }
    // Return first reference if no primary found
    for (auto* ref : it->second) {
        if (ref->getOperandIndex() == opIndex) return ref;
    }
    return nullptr;
}

int ReferenceManagerImpl::getReferenceCountTo(Address toAddr) {
    auto it = refsTo_.find(toAddr.toString());
    return (it != refsTo_.end()) ? static_cast<int>(it->second.size()) : 0;
}

int ReferenceManagerImpl::getReferenceCountFrom(Address fromAddr) {
    auto it = refsFrom_.find(fromAddr.toString());
    return (it != refsFrom_.end()) ? static_cast<int>(it->second.size()) : 0;
}

int ReferenceManagerImpl::getReferenceDestinationCount() {
    return static_cast<int>(refsTo_.size());
}

int ReferenceManagerImpl::getReferenceSourceCount() {
    return static_cast<int>(refsFrom_.size());
}

bool ReferenceManagerImpl::hasReferencesTo(Address toAddr) {
    return refsTo_.find(toAddr.toString()) != refsTo_.end();
}

Reference* ReferenceManagerImpl::updateRefType(Reference* ref, const RefType* refType) {
    if (auto* memRef = dynamic_cast<MemReferenceImpl*>(ref)) {
        // RefType change not directly supported; would need a new MemReferenceImpl
    }
    return ref;
}

void ReferenceManagerImpl::setAssociation(Symbol* s, Reference* ref) {
    // Stub
}

void ReferenceManagerImpl::removeAssociation(Reference* ref) {
    // Stub
}

bool ReferenceManagerImpl::deleteReference(Reference* ref) {
    if (!ref) return false;
    long id = ref->getID();
    auto it = references_.find(id);
    if (it != references_.end()) {
        Address fromAddr = ref->getFromAddress();
        Address toAddr = ref->getToAddress();
        references_.erase(it);
        removeFromIndex(fromAddr.toString(), ref, refsFrom_);
        removeFromIndex(toAddr.toString(), ref, refsTo_);
        return true;
    }
    return false;
}

int8_t ReferenceManagerImpl::getReferenceLevel(Address toAddr) {
    // Stub
    return 0;
}

std::vector<Reference*> ReferenceManagerImpl::getAllReferences() const {
    std::vector<Reference*> result;
    result.reserve(references_.size());
    for (const auto& pair : references_) {
        result.push_back(pair.second.get());
    }
    return result;
}

void ReferenceManagerImpl::removeFromIndex(const std::string& key, Reference* ref,
                                            std::unordered_map<std::string, std::vector<Reference*>>& index) {
    auto it = index.find(key);
    if (it != index.end()) {
        it->second.erase(std::remove(it->second.begin(), it->second.end(), ref), it->second.end());
        if (it->second.empty()) index.erase(it);
    }
}

} // namespace ghidra
