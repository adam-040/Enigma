/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionManager.cpp
/// \brief Implementation of FunctionManager
#include <ghidra/FunctionManager.h>
#include <ghidra/AutoNaming.h>
#include <algorithm>

namespace ghidra {

std::vector<std::string> FunctionManager::getCallingConventionNames() const {
    std::vector<std::string> names;
    for (const auto& pair : callingConventions_) {
        names.push_back(pair.first);
    }
    return names;
}

PrototypeModel* FunctionManager::getDefaultCallingConvention() const {
    if (defaultCallingConventionName_.empty()) return nullptr;
    auto it = callingConventions_.find(defaultCallingConventionName_);
    return (it != callingConventions_.end()) ? it->second.get() : nullptr;
}

PrototypeModel* FunctionManager::getCallingConvention(const std::string& name) const {
    auto it = callingConventions_.find(name);
    return (it != callingConventions_.end()) ? it->second.get() : nullptr;
}

Function* FunctionManager::createFunction(const std::string& name, Address entryPoint,
                                          const AddressSet& body, SourceType source) {
    perfCounters_.createFunction_calls++;
    std::string funcName = name;
    if (funcName.empty()) {
        funcName = AutoNaming::name("func", entryPoint);
    }

    // PHASE 10: O(log N) overlap check using std::set of body ranges
    // (was O(N) linear scan). The set is built lazily and incrementally maintained.
    if (sortedBodyRanges_.empty() && !functions_.empty()) {
        for (const auto& pair : functions_) {
            const AddressSet& existingBody = pair.second->getBody();
            if (existingBody.isEmpty()) continue;
            sortedBodyRanges_.insert({static_cast<uint64_t>(existingBody.getMinAddress().getOffset()),
                                       static_cast<uint64_t>(existingBody.getMaxAddress().getOffset())});
        }
    }
    Address bodyMin = body.getMinAddress();
    Address bodyMax = body.getMaxAddress();
    if (bodyMin.isValid() && bodyMax.isValid()) {
        uint64_t newStart = static_cast<uint64_t>(bodyMin.getOffset());
        uint64_t newEnd = static_cast<uint64_t>(bodyMax.getOffset());
        // Find the first range with start > newEnd (i.e., ranges ending before newStart)
        auto it = sortedBodyRanges_.upper_bound({newEnd, UINT64_MAX});
        if (it != sortedBodyRanges_.begin()) {
            --it;
            // Check if this range overlaps with [newStart, newEnd]
            if (it->first <= newEnd && newStart <= it->second) {
                throw std::invalid_argument("Overlapping function body");
            }
        }
    }

    auto func = std::make_unique<Function>(funcName, entryPoint, nullptr, source);
    func->setProgram(program_);
    func->setBody(body);
    Function* raw = func.get();
    long id = nextFunctionId_++;
    raw->setID(id);
    idIndex_[id] = raw;
    functions_[static_cast<uint64_t>(entryPoint.getOffset())] = std::move(func);
    functionsDirty_ = true;
    // PHASE 10: O(log N) insert into sorted body range set (no shift, no full rebuild)
    if (bodyMin.isValid() && bodyMax.isValid()) {
        sortedBodyRanges_.insert({static_cast<uint64_t>(bodyMin.getOffset()),
                                   static_cast<uint64_t>(bodyMax.getOffset())});
    }
    return raw;
}

Function* FunctionManager::createFunction(const std::string& name, Namespace* nameSpace,
                                          Address entryPoint, const AddressSet& body, SourceType source) {
    perfCounters_.createFunction_calls++;
    std::string funcName = name;
    if (funcName.empty()) {
        funcName = AutoNaming::name("func", entryPoint);
    }
    // PHASE 10: O(log N) overlap check using std::set
    if (sortedBodyRanges_.empty() && !functions_.empty()) {
        for (const auto& pair : functions_) {
            const AddressSet& existingBody = pair.second->getBody();
            if (existingBody.isEmpty()) continue;
            sortedBodyRanges_.insert({static_cast<uint64_t>(existingBody.getMinAddress().getOffset()),
                                       static_cast<uint64_t>(existingBody.getMaxAddress().getOffset())});
        }
    }
    Address bodyMin = body.getMinAddress();
    Address bodyMax = body.getMaxAddress();
    if (bodyMin.isValid() && bodyMax.isValid()) {
        uint64_t newStart = static_cast<uint64_t>(bodyMin.getOffset());
        uint64_t newEnd = static_cast<uint64_t>(bodyMax.getOffset());
        auto it = sortedBodyRanges_.upper_bound({newEnd, UINT64_MAX});
        if (it != sortedBodyRanges_.begin()) {
            --it;
            if (it->first <= newEnd && newStart <= it->second) {
                return nullptr;
            }
        }
    }
    auto func = std::make_unique<Function>(funcName, entryPoint, nameSpace, source);
    func->setProgram(program_);
    func->setBody(body);
    Function* raw = func.get();
    long id = nextFunctionId_++;
    raw->setID(id);
    idIndex_[id] = raw;
    functions_[static_cast<uint64_t>(entryPoint.getOffset())] = std::move(func);
    functionsDirty_ = true;
    // PHASE 10: O(log N) insert into sorted body range set
    if (bodyMin.isValid() && bodyMax.isValid()) {
        sortedBodyRanges_.insert({static_cast<uint64_t>(bodyMin.getOffset()),
                                   static_cast<uint64_t>(bodyMax.getOffset())});
    }
    return raw;
}

bool FunctionManager::removeFunction(Address entryPoint) {
    auto it = functions_.find(static_cast<uint64_t>(entryPoint.getOffset()));
    if (it == functions_.end()) return false;
    AddressSet body = it->second->getBody();
    if (!body.isEmpty()) {
        sortedBodyRanges_.erase({static_cast<uint64_t>(body.getMinAddress().getOffset()),
                                  static_cast<uint64_t>(body.getMaxAddress().getOffset())});
    }
    idIndex_.erase(it->second->getID());
    functions_.erase(it);
    functionsDirty_ = true;
    return true;
}

Function* FunctionManager::getFunctionAt(Address entryPoint) const {
    perfCounters_.getFunctionAt_calls++;
    auto it = functions_.find(static_cast<uint64_t>(entryPoint.getOffset()));
    return (it != functions_.end()) ? it->second.get() : nullptr;
}

void FunctionManager::rebuildSortedFunctions() const {
    sortedFunctions_.clear();
    sortedFunctions_.reserve(functions_.size());
    for (const auto& pair : functions_) {
        sortedFunctions_.push_back(pair.second.get());
    }
    std::sort(sortedFunctions_.begin(), sortedFunctions_.end(),
        [](Function* a, Function* b) {
            return a->getEntryPoint() < b->getEntryPoint();
        });
    functionsDirty_ = false;
}

Function* FunctionManager::getFunctionContaining(Address addr) const {
    perfCounters_.getFunctionContaining_calls++;
    if (functions_.empty()) return nullptr;
    if (functionsDirty_) rebuildSortedFunctions();

    // Binary search for the last function with entry point <= addr
    auto it = std::upper_bound(sortedFunctions_.begin(), sortedFunctions_.end(), addr,
        [](const Address& addr, Function* func) {
            return addr < func->getEntryPoint();
        });

    if (it != sortedFunctions_.begin()) {
        --it;
        if ((*it)->getBody().contains(addr)) {
            return *it;
        }
    }
    return nullptr;
}

Function* FunctionManager::getReferencedFunction(Address address) const {
    return getFunctionAt(address);
}

FunctionIterator FunctionManager::getFunctions(bool forward) const {
    if (functionsDirty_) rebuildSortedFunctions();
    if (!forward) {
        std::vector<Function*> rev(sortedFunctions_.rbegin(), sortedFunctions_.rend());
        return FunctionIterator(rev);
    }
    return FunctionIterator(sortedFunctions_);
}

FunctionIterator FunctionManager::getFunctions(Address start, bool forward) const {
    if (functionsDirty_) rebuildSortedFunctions();
    std::vector<Function*> funcs;
    if (forward) {
        auto it = std::lower_bound(sortedFunctions_.begin(), sortedFunctions_.end(), start,
            [](Function* a, const Address& addr) { return a->getEntryPoint() < addr; });
        funcs.insert(funcs.end(), it, sortedFunctions_.end());
    } else {
        auto it = std::upper_bound(sortedFunctions_.begin(), sortedFunctions_.end(), start,
            [](const Address& addr, Function* a) { return addr < a->getEntryPoint(); });
        funcs.insert(funcs.end(), sortedFunctions_.begin(), it);
        std::reverse(funcs.begin(), funcs.end());
    }
    return FunctionIterator(funcs);
}

FunctionIterator FunctionManager::getFunctions(const AddressSetView& asv, bool forward) const {
    if (functionsDirty_) rebuildSortedFunctions();
    std::vector<Function*> funcs;
    for (auto* f : sortedFunctions_) {
        if (asv.contains(f->getEntryPoint())) {
            funcs.push_back(f);
        }
    }
    if (!forward) {
        std::reverse(funcs.begin(), funcs.end());
    }
    return FunctionIterator(funcs);
}

bool FunctionManager::isInFunction(Address addr) const {
    return getFunctionContaining(addr) != nullptr;
}

Function* FunctionManager::getFunction(long key) const {
    auto it = idIndex_.find(key);
    return (it != idIndex_.end()) ? it->second : nullptr;
}

Variable* FunctionManager::getReferencedVariable(Address instrAddr, Address storageAddr,
                                                  int size, bool isRead) const {
    Function* func = getFunctionContaining(instrAddr);
    if (!func) return nullptr;
    for (auto* var : func->getLocalVariables()) {
        if (var->getMinAddress() == storageAddr) return var;
    }
    return nullptr;
}

void FunctionManager::invalidateCache(bool all) {
    if (all) {
        cache_.clear();
    }
}

} // namespace ghidra
